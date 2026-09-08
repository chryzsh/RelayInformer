import typer
import logging

from relayinformer.logger import logger
from relayinformer.commands import __all__

app = typer.Typer(
    add_completion=False,
    rich_markup_mode='rich',
    context_settings={'help_option_names': ['-h', '--help']},
    pretty_exceptions_show_locals=False
)

for command in __all__:
    app.add_typer(
        command.app,
        name=command.COMMAND_NAME,
        help=command.HELP
    )


@app.callback(no_args_is_help=True)
def main(
        # context for passing global args
        ctx: typer.Context,

        debug: bool = typer.Option(False, "--debug", "--verbose", "-v", help="Enable verbose/debug output")
    ):
    """
    Check for the presence of NTLM relay protections on LDAP, SMB, MSSQL and HTTP services
    """   

    if debug:
        logging.getLogger("relayinformer").setLevel(logging.DEBUG)
    else:
        logging.getLogger("relayinformer").setLevel(logging.INFO)

    ctx.obj = {
        "debug": debug
    }


if __name__ == "__main__":
    app()
