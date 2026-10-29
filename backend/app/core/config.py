from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    app_name: str = "CIS Compliance Auditor API"
    api_prefix: str = "/api"
    database_url: str = "sqlite:///./cis_auditor_dev.db"

    # CORS – comma-separated origins or ["*"] for dev convenience
    cors_origins: str = "http://localhost:5173,http://localhost:3000"

    # Debug mode – extra logging, NOT for production
    debug: bool = False

    model_config = SettingsConfigDict(
        env_file=".env", extra="ignore", env_file_encoding="utf-8"
    )

    @property
    def cors_origin_list(self) -> list[str]:
        return [o.strip() for o in self.cors_origins.split(",") if o.strip()]


settings = Settings()
