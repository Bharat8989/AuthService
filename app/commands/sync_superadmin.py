import click
from flask.cli import with_appcontext

from app.services.auth_account_service import AccountAuthService


@click.command("sync-superadmin")
@with_appcontext
def sync_superadmin_cli():
    success, message = AccountAuthService.sync_superadmin_logic()
    if success:
        click.echo(message)
        return
    raise click.ClickException(message)