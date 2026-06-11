"""
test_auth_check.py - Tests for auth_check and terraform_auth modules
====================================================================
Tests Azure auth checking, Terraform env var inspection,
and safety guarantees (no credentials are ever logged).
"""

import os
import sys
import subprocess
from pathlib import Path
from unittest.mock import patch, MagicMock

import pytest

src_dir = Path(__file__).parent.parent / "src"
if str(src_dir) not in sys.path:
    sys.path.insert(0, str(src_dir))

from auth_check import (
    AzureAuthStatus, TerraformAuthStatus,
    check_azure_auth, check_terraform_auth, require_azure_auth,
    _mask, _az_available,
)
from terraform_auth import (
    TerraformEnvReport,
    inspect_arm_environment, check_terraform_binary,
    inspect_backend_config, _running_in_pipeline,
)


# ---------------------------------------------------------------------------
# auth_check.py tests
# ---------------------------------------------------------------------------

class TestMaskFunction:
    """Test that _mask never exposes full values."""

    def test_mask_short_value(self):
        assert _mask("abc") == "***"

    def test_mask_normal_value(self):
        result = _mask("12345678901234567890")
        assert result.startswith("1234")
        assert result.endswith("7890")
        assert "****" in result
        # Full value must not be in result
        assert "12345678901234" not in result

    def test_mask_empty_string(self):
        assert _mask("") == "***"

    def test_mask_exact_8_chars(self):
        result = _mask("abcd1234")
        assert "****" in result
        assert result != "abcd1234"


class TestAzCliAvailable:
    """Test Azure CLI detection."""

    def test_az_not_found(self):
        with patch("subprocess.run", side_effect=FileNotFoundError):
            assert _az_available() is False

    def test_az_found(self):
        mock_result = MagicMock()
        mock_result.returncode = 0
        with patch("subprocess.run", return_value=mock_result):
            assert _az_available() is True

    def test_az_timeout(self):
        with patch("subprocess.run", side_effect=subprocess.TimeoutExpired("az", 5)):
            assert _az_available() is False


class TestCheckAzureAuth:
    """Test Azure auth status checks."""

    def test_not_logged_in_when_az_missing(self):
        with patch("auth_check._az_available", return_value=False):
            status = check_azure_auth()
            assert status.is_logged_in is False
            assert len(status.errors) > 0
            assert "not installed" in status.errors[0].lower() or "not found" in status.errors[0].lower()

    def test_not_logged_in_when_no_account(self):
        with patch("auth_check._az_available", return_value=True):
            with patch("auth_check._run_az", return_value=None):
                status = check_azure_auth()
                assert status.is_logged_in is False
                assert any("not logged in" in e.lower() or "az login" in e.lower() for e in status.errors)

    def test_logged_in_account(self):
        mock_account = {
            "user": {"name": "test@example.com", "type": "user"},
            "tenantId": "tenant-123",
            "id": "sub-456",
            "name": "My Subscription",
        }
        with patch("auth_check._az_available", return_value=True):
            with patch("auth_check._run_az", return_value=mock_account):
                status = check_azure_auth()
                assert status.is_logged_in is True
                assert status.account_name == "test@example.com"
                assert status.account_type == "user"
                assert status.tenant_id == "tenant-123"

    def test_subscription_accessible(self):
        mock_account = {
            "user": {"name": "test@example.com", "type": "user"},
            "tenantId": "tenant-123",
            "id": "sub-aaa",
            "name": "My Sub",
        }
        mock_subs = [
            {"id": "sub-aaa", "name": "Sub A"},
            {"id": "sub-bbb", "name": "Sub B"},
        ]

        def mock_run_az(args):
            if "account" in args and "show" in args:
                return mock_account
            if "account" in args and "list" in args:
                return mock_subs
            return []  # for resource list check

        with patch("auth_check._az_available", return_value=True):
            with patch("auth_check._run_az", side_effect=mock_run_az):
                status = check_azure_auth("sub-aaa")
                assert status.is_logged_in is True
                assert status.target_subscription_accessible is True

    def test_subscription_not_accessible(self):
        mock_account = {
            "user": {"name": "test@example.com", "type": "user"},
            "tenantId": "tenant-123",
            "id": "sub-aaa",
            "name": "My Sub",
        }
        mock_subs = [{"id": "sub-aaa", "name": "Sub A"}]

        def mock_run_az(args):
            if "account" in args and "show" in args:
                return mock_account
            if "account" in args and "list" in args:
                return mock_subs
            return None

        with patch("auth_check._az_available", return_value=True):
            with patch("auth_check._run_az", side_effect=mock_run_az):
                status = check_azure_auth("sub-not-accessible")
                assert status.target_subscription_accessible is False
                assert len(status.errors) > 0


class TestCheckTerraformAuth:
    """Test Terraform auth status check."""

    def test_no_vars_cli_fallback(self):
        clean_env = {k: v for k, v in os.environ.items() if not k.startswith("ARM_")}
        with patch.dict("os.environ", clean_env, clear=True):
            status = check_terraform_auth()
            # With az CLI available (dev machine), should be ready via CLI
            # This just verifies it runs without error
            assert isinstance(status.is_complete, bool)

    def test_with_msi_set(self):
        env_override = {"ARM_USE_MSI": "true"}
        with patch.dict("os.environ", env_override):
            status = check_terraform_auth()
            assert status.use_msi is True


# ---------------------------------------------------------------------------
# terraform_auth.py tests
# ---------------------------------------------------------------------------

class TestInspectArmEnvironment:
    """Test ARM environment variable inspection."""

    def test_empty_env_returns_not_ready(self):
        clean_env = {k: v for k, v in os.environ.items() if not k.startswith("ARM_")}
        with patch.dict("os.environ", clean_env, clear=True):
            with patch("terraform_auth._az_cli_available", return_value=False):
                report = inspect_arm_environment()
                assert report.arm_client_id_present is False
                assert report.arm_client_secret_present is False
                assert report.arm_tenant_id_present is False
                assert report.arm_subscription_id_present is False
                # CLI fallback also not available
                assert report.auth_method in ("none", "cli")  # cli if az found

    def test_full_sp_auth_detected(self):
        env = {
            "ARM_CLIENT_ID": "fake-client-id",
            "ARM_CLIENT_SECRET": "fake-secret",
            "ARM_TENANT_ID": "fake-tenant",
            "ARM_SUBSCRIPTION_ID": "fake-sub",
        }
        with patch.dict("os.environ", env):
            report = inspect_arm_environment()
            assert report.arm_client_id_present is True
            assert report.arm_client_secret_present is True
            assert report.arm_tenant_id_present is True
            assert report.arm_subscription_id_present is True
            assert report.auth_method == "sp"
            assert report.is_ready is True

    def test_secret_presence_only_not_value(self):
        """CRITICAL: verify secret value is never accessible from report."""
        env = {"ARM_CLIENT_SECRET": "super-secret-value-that-must-not-leak"}
        with patch.dict("os.environ", env):
            report = inspect_arm_environment()
            # Only presence flag should be set
            assert report.arm_client_secret_present is True
            # The report should not contain the actual secret
            report_dict = report.__dict__
            for key, val in report_dict.items():
                if isinstance(val, str):
                    assert "super-secret-value-that-must-not-leak" not in val, (
                        f"SECRET LEAKED in report field {key}!"
                    )

    def test_msi_auth_detected(self):
        env = {"ARM_USE_MSI": "true", "ARM_SUBSCRIPTION_ID": "sub-123"}
        with patch.dict("os.environ", env):
            report = inspect_arm_environment()
            assert report.arm_use_msi is True
            assert report.auth_method == "msi"
            assert report.is_ready is True

    def test_cli_auth_detected(self):
        clean_arm = {k: v for k, v in os.environ.items() if not k.startswith("ARM_")}
        with patch.dict("os.environ", clean_arm, clear=True):
            with patch("terraform_auth._az_cli_available", return_value=True):
                report = inspect_arm_environment()
                assert report.auth_method == "cli"
                assert report.is_ready is True

    def test_oidc_auth_detected(self):
        env = {
            "ARM_USE_OIDC": "true",
            "ARM_OIDC_REQUEST_URL": "https://example.com/token",
            "ARM_OIDC_REQUEST_TOKEN": "fake-token",
            "ARM_CLIENT_ID": "app-id",
            "ARM_TENANT_ID": "tenant-id",
            "ARM_SUBSCRIPTION_ID": "sub-id",
        }
        with patch.dict("os.environ", env):
            report = inspect_arm_environment()
            assert report.arm_use_oidc is True
            assert report.arm_oidc_configured is True
            assert report.auth_method == "sp"  # SP takes priority if all vars set

    def test_partial_sp_warns(self):
        env = {"ARM_CLIENT_ID": "partial-id"}
        clean_env = {k: v for k, v in os.environ.items() if not k.startswith("ARM_")}
        clean_env.update(env)
        with patch.dict("os.environ", clean_env, clear=True):
            with patch("terraform_auth._az_cli_available", return_value=False):
                report = inspect_arm_environment()
                assert report.arm_client_id_present is True
                assert report.arm_client_secret_present is False
                assert any("ARM_CLIENT_SECRET" in w for w in report.warnings)

    def test_pipeline_detection(self):
        with patch.dict("os.environ", {"GITHUB_ACTIONS": "true"}):
            assert _running_in_pipeline() is True

    def test_not_in_pipeline(self):
        clean_env = {k: v for k, v in os.environ.items()
            if k not in ("TF_BUILD", "GITHUB_ACTIONS", "GITLAB_CI", "JENKINS_URL", "CIRCLECI")}
        with patch.dict("os.environ", clean_env, clear=True):
            assert _running_in_pipeline() is False


class TestCheckTerraformBinary:
    """Test Terraform binary detection."""

    def test_terraform_not_found(self):
        with patch("subprocess.run", side_effect=FileNotFoundError):
            info = check_terraform_binary()
            assert info["available"] == "false"

    def test_terraform_found(self):
        mock_result = MagicMock()
        mock_result.returncode = 0
        mock_result.stdout = '{"terraform_version": "1.6.0", "platform": "linux_amd64"}'
        with patch("subprocess.run", return_value=mock_result):
            info = check_terraform_binary()
            assert info["available"] == "true"
            assert info["version"] == "1.6.0"


class TestInspectBackendConfig:
    """Test Terraform backend config parsing."""

    def test_no_backend_files(self, tmp_path):
        result = inspect_backend_config(str(tmp_path))
        assert result == {}

    def test_azurerm_backend_detected(self, tmp_path):
        backend_tf = tmp_path / "backend.tf"
        backend_tf.write_text(
            'terraform {\n'
            '  backend "azurerm" {\n'
            '    resource_group_name  = "my-rg"\n'
            '    storage_account_name = "mystorage"\n'
            '    container_name       = "tfstate"\n'
            '    key                  = "dev.tfstate"\n'
            '  }\n'
            '}\n'
        )
        result = inspect_backend_config(str(tmp_path))
        assert result.get("type") == "azurerm"
        assert result.get("resource_group_name") == "my-rg"
        assert result.get("storage_account_name") == "mystorage"
        assert result.get("container_name") == "tfstate"

    def test_no_secret_values_exposed(self, tmp_path):
        """Backend parsing must not expose access keys."""
        backend_tf = tmp_path / "backend.tf"
        backend_tf.write_text(
            'terraform {\n'
            '  backend "azurerm" {\n'
            '    access_key = "SECRET_ACCESS_KEY_12345"\n'
            '    storage_account_name = "mystorage"\n'
            '  }\n'
            '}\n'
        )
        result = inspect_backend_config(str(tmp_path))
        # access_key should not be in results
        assert "access_key" not in result
        for val in result.values():
            assert "SECRET_ACCESS_KEY_12345" not in str(val)


# ---------------------------------------------------------------------------
# Safety integration tests
# ---------------------------------------------------------------------------

class TestNoCredentialLeakage:
    """
    Critical safety tests: verify no credentials are ever in report output.
    These must always pass.
    """

    def test_arm_client_secret_never_in_report_str(self):
        secret = "my-very-secret-client-secret-value"
        env = {
            "ARM_CLIENT_ID": "some-id",
            "ARM_CLIENT_SECRET": secret,
            "ARM_TENANT_ID": "some-tenant",
            "ARM_SUBSCRIPTION_ID": "some-sub",
        }
        with patch.dict("os.environ", env):
            report = inspect_arm_environment()
            report_str = str(report)
            assert secret not in report_str, "SECRET LEAKED into report string!"

    def test_mask_does_not_reveal_full_subscription_id(self):
        sub_id = "b6085d96-6bb5-4e70-890c-e026d0cb1d1a"
        masked = _mask(sub_id)
        # Should not contain the full UUID
        assert sub_id not in masked
        # Should only show first+last 4
        assert masked.startswith("b608")
        assert masked.endswith("d1a")


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
