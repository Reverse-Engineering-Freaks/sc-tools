# sc-tools

Tools for exploration inside Smart Cards

## Summary

This software provides a wide range of functions, from basic Smart Card operations to special functions for exploration inside Smart Cards. It can also be used as a library and has a CLI application that can specify a series of operations by arguments.

## Usage

### sc-explorer (CLI application)

This application made by [Python Fire](https://github.com/google/python-fire). Please read [The Python Fire Guide](https://github.com/google/python-fire/blob/master/docs/guide.md) and following.

```
$ sc-explorer -- --help

NAME
    sc-explorer - SC Explorer CLI

SYNOPSIS
    sc-explorer <flags>

DESCRIPTION
    SC Explorer CLI

FLAGS
    -n, --nfc=NFC
        Default: False
        Use NFC reader. Defaults to False.
    -r, --reader=READER
        Default: 0
        Reader descriptor. Reader name or index in list. Defaults to 0.
    --auto_get_response=AUTO_GET_RESPONSE
        Default: True
        Enable automatic getting remaining response data. Defaults to True.
    --allow_extended_apdu=ALLOW_EXTENDED_APDU
        Default: False
        Allow Extended APDU. Defaults to False.
    -t, --transceive_log_dir=TRANSCEIVE_LOG_DIR
        Default: './transceive_logs/'
        Transceive log directory path. Defaults to "./transceive_logs/".
    -l, --log_level=LOG_LEVEL
        Default: 'INFO'
        Log level. Defaults to "INFO". {CRITICAL|FATAL|ERROR|WARN|WARNING|INFO|DEBUG|NOTSET}
```

#### Commands

##### View detail of a command

Example

```
$ sc-explorer command -- --help

NAME
    sc-explorer command - Send Command APDU

SYNOPSIS
    sc-explorer - command COMMAND

DESCRIPTION
    Send Command APDU

POSITIONAL ARGUMENTS
    COMMAND
        Command APDU as hex string

NOTES
    You can also use flags syntax for POSITIONAL ARGUMENTS
```

##### List of command

```
command
    Send Command APDU

dump_response
    Dump last response data

get_data
    GET DATA

get_response
    GET RESPONSE

jpki_sign
    JPKI Sign (PERFORM SECURITY OPERATION)

list_cla_ins
    List valid CLA-INS

list_do
    List Data Object

list_ef
    List EF

list_p1_p2
    List valid P1-P2

print_response
    Print last response

read_binary
    READ (ALL) BINARY

read_record
    READ RECORD(S)

search_df
    Search DF

select_df
    SELECT FILE (DF)

select_ef
    SELECT FILE (EF)

verify
    VERIFY
```

#### Example

```
$ sc-explorer - select-df \"D392F000260100000001\" - select-ef \"0002\" - read-binary
Data:
0x00000000    30 82 05 14 30 82 03 FC A0 03 02 01 02 02 04 06    0...0...........
0x00000010    7C 6A 21 30 0D 06 09 2A 86 48 86 F7 0D 01 01 0B    |j!0...*.H......
0x00000020    05 00 30 81 80 31 0B 30 09 06 03 55 04 06 13 02    ..0..1.0...U....
0x00000030    4A 50 31 0D 30 0B 06 03 55 04 0A 0C 04 4A 50 4B    JP1.0...U....JPK
0x00000040    49 31 23 30 21 06 03 55 04 0B 0C 1A 4A 50 4B 49    I1#0!..U....JPKI
0x00000050    20 66 6F 72 20 64 69 67 69 74 61 6C 20 73 69 67     for digital sig
0x00000060    6E 61 74 75 72 65 31 3D 30 3B 06 03 55 04 0B 0C    nature1=0;..U...
0x00000070    34 4A 61 70 61 6E 20 41 67 65 6E 63 79 20 66 6F    4Japan Agency fo
0x00000080    72 20 4C 6F 63 61 6C 20 41 75 74 68 6F 72 69 74    r Local Authorit
0x00000090    79 20 49 6E 66 6F 72 6D 61 74 69 6F 6E 20 53 79    y Information Sy
0x000000A0    73 74 65 6D 73 30 1E 17 0D 32 33 30 37 31 36 30    stems0...2307160
0x000000B0    30 35 30 32 37 5A 17 0D 33 33 30 37 31 35 31 34    05027Z..33071514
0x000000C0    35 39 35 39 5A 30 81 80 31 0B 30 09 06 03 55 04    5959Z0..1.0...U.
0x000000D0    06 13 02 4A 50 31 0D 30 0B 06 03 55 04 0A 0C 04    ...JP1.0...U....
0x000000E0    4A 50 4B 49 31 23 30 21 06 03 55 04 0B 0C 1A 4A    JPKI1#0!..U....J
0x000000F0    50 4B 49 20 66 6F 72 20 64 69 67 69 74 61 6C 20    PKI for digital 
0x00000100    73 69 67 6E 61 74 75 72 65 31 3D 30 3B 06 03 55    signature1=0;..U
(Omitted)
0x00000760    00 00 00 00 00 00 00 00 00 00 00 00                ............
SW: 0x9000 (NORMAL_END)
```

## Authors

- [soltia48](https://github.com/soltia48)

## License

[MIT](https://opensource.org/licenses/MIT)

Copyright (c) 2024 Reverse Engineering Freaks OSS Project
