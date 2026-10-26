import os


def service_password():
    # Deployment provides the credential; missing configuration fails explicitly.
    return os.environ["LOMO_DEMO_PASSWORD"]
