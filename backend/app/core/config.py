from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    app_name: str = "CIS Compliance Auditor API"
    api_prefix: str = "/api"
    database_url: str = "sqlite:///./cis_auditor_dev.db"

    model_config = SettingsConfigDict(env_file=".env", extra="ignore")


settings = Settings()
