#!/usr/bin/env python3

import typer
from lib.commands import find, mssql, http, dpapi
from lib.scripts.banner import small_banner



app = typer.Typer(
    no_args_is_help=True,
    add_completion=False,
    rich_markup_mode='rich',
    context_settings={'help_option_names': ['-h', '--help']},
    pretty_exceptions_show_locals=False
)


app.add_typer(
    find.app,
    name=find.COMMAND_NAME,
    help=find.HELP
)

app.add_typer(
    http.app,
    name=http.COMMAND_NAME,
    help=http.HELP
)

# app.add_typer(
#     mssql.app,
#     name=mssql.COMMAND_NAME,
#     help=mssql.HELP
# )

# app.add_typer(
#     dpapi.app,
#     name=dpapi.COMMAND_NAME,
#     help=dpapi.HELP
# )

if __name__ == '__main__':
    small_banner()
    app(prog_name='scomhunter')
