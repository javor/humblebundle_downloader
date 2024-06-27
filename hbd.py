#!/usr/bin/env python3
import dataclasses
import datetime
import functools
import hashlib
import io
import json
import logging.config
import os
import pathlib
import re
import shutil
import string
import time
import typing
import unicodedata
import urllib
import urllib.error
import urllib.parse
import urllib.request

import click

# -------------------------------------------------------------------------------------
# envs


@functools.cache
def get_session_key():
    return os.getenv(key="HUMBLE_BUNDLE_SESSION_KEY")


@functools.cache
def get_dest_dir_structure():
    return os.getenv(
        key="DEST_DIR_STRUCTURE",
        default=(
            "$created_Y/"
            "humblebundle.com/"
            "Product - $product_name/"
            "Subproduct - $subproduct_name"
        ),
    )


@functools.cache
def get_sanitize_chars_map():
    if x := os.getenv(key="SANITIZE_CHARS_MAP"):
        return json.loads(x)
    else:
        # https://en.wikipedia.org/wiki/Filename#Reserved_characters_and_words
        return {c: " - " for c in ["/", "\\", "?", "%", "*", ":", "|", '"', "<", ">"]}


def inject(valuefunc, argname):
    """
    Injects result of `valuefunc` (if not None) at the specified place (`argname`) in
    the decorated function.
    """

    def inject_outer(func):

        @functools.wraps(func)
        def wrapper(*args, **kwargs):

            if argvalue := valuefunc():
                kwargs[argname] = argvalue

            return func(*args, **kwargs)

        return wrapper

    return inject_outer


# -------------------------------------------------------------------------------------
# vars


APP_NAME = "com.github.javor.humblebundle_downloader"

URL = "https://www.humblebundle.com"


# -------------------------------------------------------------------------------------
# logging

logging_config_file = pathlib.Path(__file__).parent.absolute() / "hbd.ini"

logging.config.fileConfig(logging_config_file, encoding="utf-8")

logger = logging.getLogger(APP_NAME)


# -------------------------------------------------------------------------------------
# data model


@dataclasses.dataclass
class Metadata:

    order_id: str

    product_name: str

    product_machine_name: str

    subproduct_name: str

    subproduct_machine_name: str

    subproduct_tag: str

    filesize_bytes: str

    filesize_human: str

    platform: str


@dataclasses.dataclass
class Digest:

    algo: str | None

    hash: str | None


@dataclasses.dataclass
class Link:

    url: str

    digest: Digest

    @property
    def expiry(self) -> int:  # unix timestamp
        return int(re.search("~exp=(.*)~hmac=", self.url).group(1))


@dataclasses.dataclass
class TransferCommand:

    metadata: Metadata

    source_link: Link

    target_file: pathlib.Path


# -------------------------------------------------------------------------------------
# exception


class AppError(Exception):
    """
    Base exception used by this module.
    """


class TransferError(AppError):
    """
    Base exception for transfer errors.
    """


class IntegrityCheckError(TransferError):
    """
    Exception for integrity check errors.
    """


class LinkExpiredError(TransferError):
    """
    Exception for link expired errors.
    """


class OrderNoExistsError(AppError):
    """
    Exception for order no exists errors.
    """


class OrderNotFoundError(AppError):
    """
    Exception for order not found errors.
    """


def with_error_handling(func):
    """
    Performs error handling around decorated function.
    """

    @functools.wraps(func)
    def wrapper(*args, **kwargs):

        try:
            return func(*args, **kwargs)

        except OrderNotFoundError as e:
            logger.error(e, exc_info=True)
            raise click.ClickException(
                str(e) + " Use 'fetch' to obtain fresh details about files."
            )

        except LinkExpiredError as e:
            logger.error(e, exc_info=True)
            raise click.ClickException(
                str(e) + " Use 'fetch' to obtain fresh details about files."
            )

        except Exception as e:
            logger.error(e, exc_info=True)
            raise click.ClickException(str(e))

    return wrapper


# -------------------------------------------------------------------------------------
# external api


@inject(get_session_key, argname="session_key")
def _prepare_cookie_header(session_key=None) -> str:

    cookie_header = {}

    if session_key:
        cookie_header.update({"_simpleauth_sess": session_key})

    return "; ".join([f"{name}={value}" for name, value in cookie_header.items()])


# ------------------
# /api/v1/user/order
# ------------------
def get_user_orders() -> typing.List[typing.Dict[str, str]]:
    """
    Sends a request to the '/api/v1/user/order' endpoint to retrieve the IDs of orders
    purchased by the user.

    :return: A list of dictionaries, each containing a 'gamekey' (order ID).
    """

    response = urllib.request.urlopen(
        urllib.request.Request(
            f"{URL}/api/v1/user/order",
            headers={"Cookie": _prepare_cookie_header()},
        ),
    )

    body = response.read()

    return json.loads(body.decode("utf-8"))


# --------------
# /api/v1/orders
# --------------
def get_orders(
    user_orders: typing.List[typing.Dict[str, str]]
) -> typing.Dict[str, dict]:
    """
    Sends a request to the '/api/v1/orders' endpoint to retrieve details about orders
    purchased by the user.

    :param user_orders: A list of dictionaries, each containing a 'gamekey' (order ID).
    :return: A dictionary where each key corresponds to a 'gamekey' from 'user_order',
             with the associated value containing the attributes of the element.
    """

    query_params = [("all_tpkds", "true")]
    query_params.extend(
        [("gamekeys", user_order.get("gamekey")) for user_order in user_orders]
    )
    query_params = urllib.parse.urlencode(query_params)

    response = urllib.request.urlopen(
        urllib.request.Request(
            f"{URL}/api/v1/orders?{query_params}",
            headers={"Cookie": _prepare_cookie_header()},
        ),
    )

    body = response.read()

    return json.loads(body.decode("utf-8"))


# -------------------------------------------------------------------------------------
# internal


@functools.cache
def get_repo():
    """
    Returns a repository object that supports adding, getting, and listing purchased
    orders from/to local storage.

    :return: A repository object.
    """

    data_dir = pathlib.Path(click.get_app_dir(APP_NAME, roaming=False)) / "orders"

    if not data_dir.exists():
        data_dir.mkdir(exist_ok=True, parents=True)

    class _Repository:

        suffix = ".json"

        def get(self, order_id: str) -> dict:
            path = data_dir / f"{order_id}{self.suffix}"
            with path.open(mode="r", encoding="utf-8") as f:
                return json.load(f)

        def get_ids(self) -> typing.List[str]:
            return [x.name.replace(self.suffix, "") for x in data_dir.iterdir()]

        def put(self, order_id: str, order: dict) -> None:
            path = data_dir / f"{order_id}{self.suffix}"
            with path.open(mode="w", encoding="utf-8") as f:
                json.dump(order, f, ensure_ascii=False, indent=4, sort_keys=True)

    return _Repository()


def order_gen():
    """
    Returns a generator that yields purchased orders based on the data on remote end.

    :return: A generator of purchased orders.
    """

    class _Generator(object):

        def __init__(self):
            self._iter_ids = []

        def __iter__(self):
            for x in self.iter_ids:
                yield get_orders([{"gamekey": x}])

        def __len__(self):
            return len(self.iter_ids)

        @functools.cached_property
        def ids(self):
            return [x.get("gamekey") for x in get_user_orders()]

        @property
        def iter_ids(self):
            if self._iter_ids:
                return self._iter_ids
            return self.ids

        def with_ids(self, ids: typing.List[str]):
            if not all(x in self.ids for x in ids):
                raise OrderNoExistsError(
                    "Some of the provided IDs do not exist on the server."
                )
            self._iter_ids.extend(ids)
            return self

    return _Generator()


def local_order_gen():
    """
    Returns a generator that yields purchased orders based on the data on local end.

    :return: A generator of purchased orders.
    """

    repo = get_repo()

    class _Generator(object):

        def __init__(self):
            self._iter_ids = []

        def __iter__(self):
            for x in self.iter_ids:
                yield repo.get(x)

        def __len__(self):
            return len(self.iter_ids)

        @functools.cached_property
        def ids(self):
            return repo.get_ids()

        @property
        def iter_ids(self):
            if self._iter_ids:
                return self._iter_ids
            return self.ids

        def with_ids(self, ids: typing.List[str]):
            if not all(x in self.ids for x in ids):
                raise OrderNotFoundError(
                    "Some of the provided IDs were not found in the local storage."
                )
            self._iter_ids.extend(ids)
            return self

    return _Generator()


@inject(get_dest_dir_structure, argname="dest_dir_structure")
def transfer_command_gen(
    order: typing.Dict, *, work_dir=".", dest_dir_structure=None, torrent_file=False
) -> typing.Iterable[TransferCommand]:
    """
    Returns a generator that yields transfer commands.

    :param order: A dictionary object representing the details of an order obtained
                  from the '/api/v1/orders' endpoint.
    :param work_dir: The working directory to use when creating the target_path.
    :param dest_dir_structure: A template for generating the directory structure of
                               the dest_dir.
    :param torrent_file: Indicates if the source_link should reference a torrent file.
    :return: A generator of transfer commands.
    """

    def url_path_name(url: str):
        return pathlib.Path(urllib.parse.urlparse(url).path).name

    gamekey = order.get("gamekey")
    product = order.get("product")
    created = datetime.datetime.fromisoformat(order.get("created"))

    for subproduct in order.get("subproducts"):

        for download in subproduct.get("downloads"):

            for download_struct in download.get("download_struct"):

                metadata = Metadata(
                    order_id=gamekey,
                    product_name=product.get("human_name"),
                    subproduct_name=subproduct.get("human_name"),
                    product_machine_name=product.get("machine_name"),
                    subproduct_machine_name=subproduct.get("machine_name"),
                    subproduct_tag=download_struct.get("name"),
                    filesize_bytes=download_struct.get("file_size"),
                    filesize_human=download_struct.get("human_size"),
                    platform=download.get("platform"),
                )

                digest = Digest(
                    algo=None,
                    hash=None,
                )

                if not torrent_file:
                    sha1, md5 = download_struct.get("sha1"), download_struct.get("md5")

                    # sometimes the hash value is garbage, need to check for its format...
                    if not digest.algo and sha1 and re.match(r"^[0-9a-f]{40}$", sha1):
                        digest = Digest(
                            algo="sha1",
                            hash=sha1,
                        )

                    # sometimes the hash value is garbage, need to check for its format...
                    if not digest.algo and md5 and re.match(r"^[a-fA-F\d]{32}$", md5):
                        digest = Digest(
                            algo="md5",
                            hash=md5,
                        )

                if torrent_file:
                    source_link = Link(
                        url=download_struct.get("url").get("bittorrent"),
                        digest=digest,
                    )
                else:
                    source_link = Link(
                        url=download_struct.get("url").get("web"),
                        digest=digest,
                    )

                dest_dir = ""

                if x := dest_dir_structure:
                    subs = {
                        **dataclasses.asdict(metadata),
                        "created_Y": created.strftime("%Y"),
                        "created_M": created.strftime("%M"),
                        "created_d": created.strftime("%d"),
                    }

                    subs = {k: _sanitize_name(str(v)) for k, v in subs.items()}

                    dest_dir = string.Template(x).substitute(subs)

                target_file = (
                    pathlib.Path(work_dir) / dest_dir / url_path_name(source_link.url)
                )

                command = TransferCommand(
                    metadata=metadata, source_link=source_link, target_file=target_file
                )

                yield command


@inject(get_sanitize_chars_map, argname="chars_map")
def _sanitize_name(name: str, ensure_ascii=True, chars_map=None) -> str:
    """
    Performs the cleaning process on the provided name.

    :param name: The name to be cleaned.
    :param ensure_ascii: Specifies whether the cleaned name should consist only
                         of ASCII characters.
    :param chars_map: A dictionary where key represents a character to be replaced,
                      and its corresponding value is the substitution.
    :return: A string representing the cleaned name.
    """

    # substitute unicode characters with corresponding ones in ascii
    if ensure_ascii:
        name = unicodedata.normalize("NFKD", name)
        name = name.encode("ascii", "ignore").decode("utf-8")

    # substitute invalid characters
    if chars_map:
        name = name.translate(str.maketrans(chars_map))

    name = re.sub(r" +", " ", name)
    name = re.sub(r"\n", " ", name)
    name = name.strip()

    return name


def transfer_file(command: TransferCommand):
    """
    Transfers the file specified in the command.

    :param command: The command used to transfer the file.
    :return: None.
    """

    url, expiry = command.source_link.url, command.source_link.expiry

    if time.time() > expiry:
        raise LinkExpiredError(
            f"Cannot transfer file: "
            f"'{url}' expired on {datetime.datetime.fromtimestamp(expiry)}."
        )

    _download_file(url, command.target_file)


def _download_file(source: str, target: pathlib.Path):
    """
    Downloads a file from the source (remote) to the target path (local).

    If the directory structure for the target path does not exist, it will be created.

    :param source: The URL of the file to be downloaded.
    :param target: The file system path where the downloaded file should be written.
    :return: None
    """

    if target.exists():
        return

    if not target.parent.exists():
        os.makedirs(target.parent)

    if not target.parent.is_dir():
        raise TransferError(
            f"Cannot download file: '{target.parent}' is not a directory."
        )

    part = target.with_suffix(".part")

    if part.exists():
        raise TransferError(f"Cannot download file: '{part}' already exists.")

    try:
        with part.open(mode="wb") as f:
            with urllib.request.urlopen(source) as resp:
                shutil.copyfileobj(resp, f)
        shutil.move(part, target)

    finally:
        part.unlink(missing_ok=True)


def _digest(path: pathlib.Path, algo: str) -> Digest:
    """
    Generates a digest object for the contents of a file located at the given path.

    :param path: The file system path to be used for generating a digest.
    :param algo: The hash algorithm to be used for generating the digest.
    :return: A digest object.
    """

    if not path.exists():
        raise IntegrityCheckError(f"'{path}' does not exist.")

    if algo not in hashlib.algorithms_available:
        raise IntegrityCheckError(f"'{algo}' is not a supported hash algorithm.")

    f: io.BufferedReader

    with path.open(mode="rb") as f:
        return Digest(algo=algo, hash=hashlib.file_digest(f, algo).hexdigest())


# -------------------------------------------------------------------------------------
# cli interface


@click.group()
def cli(): ...


@click.option(
    "--work-dir",
    help="Work in this directory instead of the current one.",
    type=click.Path(exists=False, file_okay=False, dir_okay=True),
    default=".",
)
@click.option(
    "--verify",
    help="Verify primary files digest.",
    is_flag=True,
)
@click.option(
    "--torrent",
    help="Download torrent files instead of primary files.",
    is_flag=True,
)
@click.option(
    "--no-color",
    help="Do not print colors in the output.",
    is_flag=True,
)
@click.option(
    "--dry-run",
    help="Preview files for download without downloading them.",
    is_flag=True,
)
@click.argument(
    "order_ids",
    nargs=-1,
)
@cli.command(name="download", short_help="Download files.")
def cli_download(*args, dry_run, **kwargs):
    """
    Transfers downloadable files from purchases to the local file system.

    Make sure to first obtain details about files by using a fetch command.
    """

    if dry_run:
        return _cli_download_dry_run(*args, **kwargs)
    else:
        return _cli_download(*args, **kwargs)


@with_error_handling
def _cli_download_dry_run(work_dir, torrent, order_ids, **_kwargs):

    orders = local_order_gen().with_ids(order_ids)

    click.echo("--- Dry Run: Downloading Files ---")

    for order in orders:

        contents = []

        commands = transfer_command_gen(order, work_dir=work_dir, torrent_file=torrent)

        commands = sorted(commands, key=lambda x: len(x.source_link.url), reverse=True)

        commands = list(commands)

        for command in commands:

            contents.append(
                f"Downloading: {command.source_link.url}\n"
                f"to: '{command.target_file.absolute()}'\n"
            )

        click.echo("\n".join(contents), nl=False)

    click.echo("--- Dry Run Completed ---")


@with_error_handling
def _cli_download(work_dir, verify, torrent, no_color, order_ids, **_kwargs):

    echo_params = {"color": not no_color}

    orders = local_order_gen().with_ids(order_ids)

    number_of_orders = len(orders.ids)

    for i, order in enumerate(orders):

        commands = transfer_command_gen(order, work_dir=work_dir, torrent_file=torrent)

        commands = sorted(commands, key=lambda x: len(x.source_link.url), reverse=True)

        commands = list(commands)

        number_of_commands = len(commands)

        for j, command in enumerate(commands):

            click.echo() if not (i == 0 and j == 0) else ...

            click.echo(
                f"Downloading "
                f"({j+1}/{number_of_commands} | {i + 1}/{number_of_orders})"
                f": "
                f"{command.source_link.url}"
                f" ",
                nl=False,
                **echo_params,
            )

            transfer_file(command)

            click.echo(click.style("Done", fg="green"), **echo_params)

            if verify:
                _algo = command.source_link.digest.algo
                _hash = command.source_link.digest.hash

                result = None
                if _algo:
                    result = _digest(command.target_file, _algo)

                if not result:
                    click.echo(
                        f"Verifying: {click.style('Skipped', fg='yellow')}",
                        **echo_params,
                    )
                elif result.hash == _hash:
                    click.echo(
                        f"Verifying: {click.style('Correct', fg='green')}",
                        **echo_params,
                    )
                else:
                    click.echo(
                        f"Verifying: {click.style('Corrupt', fg='red')}"
                        f" "
                        f"('{_hash}' != '{result.hash}')",
                        **echo_params,
                    )


@click.argument(
    "order_ids",
    nargs=-1,
)
@cli.command(name="fetch", short_help="Collect details about files to download.")
def cli_fetch(*args, **kwargs):
    """
    Collects details about files to download and stores them locally.
    """

    return _cli_fetch(*args, **kwargs)


@with_error_handling
def _cli_fetch(order_ids, **_kwargs):

    orders = order_gen().with_ids(order_ids)

    with click.progressbar(
        iterable=orders, label="Fetching", show_pos=True, width=0
    ) as progressbar:

        repo = get_repo()

        for order in progressbar:

            for key, value in order.items():

                repo.put(key, value)

        progressbar.render_finish()


@click.option(
    "--human-readable",
    help="Print file sizes in human readable format.",
    is_flag=True,
)
@click.option(
    "--horizontal",
    help="Print file details in a horizontal format.",
    is_flag=True,
)
@click.option(
    "--no-color",
    help="Do not print colors in the output.",
    is_flag=True,
)
@click.option(
    "--no-label",
    help="Do not print labels in the output.",
    is_flag=True,
)
@click.argument(
    "order_ids",
    nargs=-1,
)
@cli.command(name="ls", short_help="Display details about files to download.")
def cli_ls(*args, **kwargs):
    """
    Displays details about files to download.

    Make sure to first obtain details about files by using a fetch command.
    """

    return _cli_ls(*args, **kwargs)


@with_error_handling
def _cli_ls(human_readable, horizontal, no_color, no_label, order_ids, **_kwargs):

    echo_params = {"color": not no_color}

    def label(text):
        return "" if no_label else text

    orders = local_order_gen().with_ids(order_ids)

    for order in orders:

        contents = []

        commands = list(transfer_command_gen(order))

        for command in commands:

            _id = click.style(
                command.metadata.order_id,
                **{"fg": "magenta"},
            )

            _product = click.style(
                command.metadata.product_name,
                **{"fg": "green"},
            )

            _subproduct = click.style(
                command.metadata.subproduct_name,
                **{"fg": "blue"},
            )

            _tags = click.style(
                command.metadata.subproduct_tag,
                **{"fg": "cyan"},
            )

            _filesize = click.style(
                (
                    f"{command.metadata.filesize_human}"
                    if human_readable
                    else f"{command.metadata.filesize_bytes}"
                ),
                **{"fg": "yellow"},
            )

            separator = " | " if horizontal else "\n"

            contents.append(
                # fmt: off
                f"{label('Id: ')}{_id}"
                f"{separator}"

                f"{label('Product: ')}{_product}"
                f"{separator}"

                f"{label('Subproduct: ')}{_subproduct}"
                f"{separator}"

                f"{label('Tags: ')}{_tags}"
                f"{separator}"

                f"{label('Size: ')}{_filesize}"

                "\n"
                # fmt: on
            )

        click.echo(
            f"{'' if horizontal else '\n'}".join(contents), nl=False, **echo_params
        )


if __name__ == "__main__":
    cli()
