import click
from flask.cli import with_appcontext

from app.services.auth_service import AuthService


@click.command("sync-superadmin")
@with_appcontext
def sync_superadmin_cli():
    success, message = AuthService.sync_superadmin_logic()
    if success:
        click.echo(message)
        return
    raise click.ClickException(message)