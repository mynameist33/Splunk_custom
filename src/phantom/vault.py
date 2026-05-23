import tempfile


class Vault:
    @staticmethod
    def get_vault_tmp_dir() -> str:
        return tempfile.gettempdir()
