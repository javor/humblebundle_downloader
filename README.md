# humblebundle_downloader

A tool to download files from Humble Bundle Library.

## Installation

1. Clone the repository:

    ```bash
    git clone https://github.com/javor/humblebundle_downloader.git
    ```

2. Navigate to the project directory:

    ```bash
    cd humblebundle_downloader
    ```

3. Install the project:

    ```bash
    pip install --editable .
    ```

## Usage

```bash
Usage: hbd [OPTIONS] COMMAND [ARGS]...

Options:
  --help  Show this message and exit.

Commands:
  download  Download files.
  fetch     Collect details about files to download.
  ls        Display details about files to download.
```

### Example:

```bash
$ export HUMBLE_BUNDLE_SESSION_KEY=... # 1. provide value of `_simpleauth_sess` from cookies
$ hbd fetch                            # 2. collect details about files (required before downloading)
$ hbd download --dry-run               # 3. preview files for download
$ hbd download --verify                # 4. start the download process and verify the digest
```

## License

[MIT](https://choosealicense.com/licenses/mit/)
