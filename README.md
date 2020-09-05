# vtutil
**vtutil** is a python wrapper for Virustotal [V2](https://developers.virustotal.com/reference) and [V3](https://developers.virustotal.com/v3.0/reference) API.

### Initializing vtutil

`import vtutil`

`vt3 = vtutil.VTUtilsV3("Your_VT_API_KEY")` \# to instantiate V3 API

`vt2 = vtutil.VTUtilsV2("Your_VT_API_KEY")` \# to instantiate V2 API


#### Getting File Report 

`vt3.getfileReportv3("hash_of_file"))`

#### Getting File Behavior

`vt3.getfileBehaviorv3("hash_of_file")`

#### Download a File

`vt3.get_file("hash", "output_directory")`

#### Get the malware name based on vendor detections

```
vt3.getClassification(vt3.getfileReportv3("hash_of_file"))
```

The above code will return a json format which indicates the category and family of the hash. For example:
```
vt3.getClassification(vt3.getfileReportv3(b94ba37e5956e4880d7bcc1ff93419e73771416980f54b221e16701660e5571a))
```

The above query wil return:

```
{'av': {'kaspersky': 'Trojan.Win32.Streamer.sy',
        'malwarebytes': 'Trojan.MalPack.TRE',
        'microsoft': 'Ransom:Win32/WastedLocker.SK!MTB',
        'sophos': 'Mal/EncPk-APV'},
 'category': 'Ransom',
 'family': 'wastedlocker'}

```

## vttool

**vttool** is a python utility for several use cases of **vtutil**


`python vttool.py -h`

```
usage: vttool.py [-h] [--get_hunt_notifications] [--filter FILTER]
                 [--limit LIMIT] [--download DOWNLOAD]
                 [--download_list DOWNLOAD_LIST] [--out OUT]
                 [--first_seen FIRST_SEEN] [--search SEARCH] [--get_hashes]
                 [--log LOG]

This is a utility for vtutil use cases

optional arguments:
  -h, --help            show this help message and exit
  --get_hunt_notifications
                        Get files hit by your livehunt rules. You can use this
                        in conjunction with --filter
  --filter FILTER       This is a filter used in conjunction with other
                        arguments like --get_hunt_notifications
  --limit LIMIT         Limit for search and notifications
  --download DOWNLOAD   Hash of the file you want to download in VT
  --download_list DOWNLOAD_LIST
                        File containing hashes to download
  --out OUT             Output dir to save files, pcaps, etc
  --first_seen FIRST_SEEN
                        First seen date from to show, e.g. 2020-01-30. This is
                        useful when filtering new files only
  --search SEARCH       Search VT and return sha256 list. e.g --search
                        "tag:doc positives:10+"
  --get_hashes          Get a list of hashes only in conjunction with --search
                        e.g., --get_hashes --search positives:10+
  --log LOG             Log level, INFO, DEBUG, WARNING, etc
  ```
  
  #### Search for 1000 hashes with positives>10 and with tag "macros"
  `python vttool.py --get_hashes --search "positives:10+ tag:macros" --limit 1000`
  ```
sha256: 8b23e164f16ba0caed21611db9782895ac3a6a1f5b30a16e7cff6a2f8e3c3008
sha256: ef7cf4395e6f154ad0deda89d832839b0301a4973ac6c002652d2cf6cf185ee9
sha256: d4c076603f475a562c8771e360b65b734aba563731f4417b117ecfad4297d562
sha256: 1e52c0f38822abee6f044ad1cadcd997d709163955787be931b19bdadab0b376
sha256: 9d50d006378522d4af924f66889b7d818a3660fb1f59e87b2482bf87683ddc65
sha256: 52646e971288c190bffe00616c46fdb3741f1be6a5f0fe2235ca71c24435bf65
sha256: 0274b67e43f98e65033f7b7b9c341a6560e515e61187693dfa5b941a2545309f
sha256: 7c88f52c679aeb917f52a42b5424f5aeb90901cd44d00fe9aa0608e4f2940cb4
..............
{redacted}

  ```

#### Get information about the hashes that hit with your hunting rules

`python vttool.py --get_hunt_notifications --filter "vba_agressive_hunt"` # vba_agressive_hunt is the name of your livehunt rule

```
---------------------------------+----+--------------------+----------------------------------------------------------------------------------------------------+----------
md5                              |hits|rule                |Details                                                                                             |first_seen
---------------------------------+----+--------------------+----------------------------------------------------------------------------------------------------+----------
00f7cf1c64f887618901e20cdf4211c0 |40  |vba_agressive_hunt  |MALWARE_NAME: TrojanDownloader.emotet                                                               |2020-09-01
                                 |    |                    |NAME: PO# 09012020Ex.doc                                                                            |16:54:25
                                 |    |                    |FILE_TYPE: MS Word Document                                                                         |
                                 |    |                    |TAGS: obfuscated,doc,macros,executes-dropped-file,hide-app,create-ole                               |
                                 |    |                    |NAMES: PO# 09012020Ex.doc                                                                           |
---------------------------------+----+--------------------+----------------------------------------------------------------------------------------------------+----------
24566d86cde863786f1545db08a35a1e |34  |vba_agressive_hunt  |MALWARE_NAME: TrojanDownloader.emotet                                                               |2020-09-03
                                 |    |                    |NAME: ARC 20200903 52144.doc                                                                        |19:12:11
                                 |    |                    |FILE_TYPE: MS Word Document                                                                         |
                                 |    |                    |TAGS: obfuscated,doc,macros,executes-dropped-file,hide-app,create-ole                               |
                                 |    |                    |NAMES: ARC 20200903 52144.doc,emotet_e1_490fef6aff98d6e725d22acf348a7bc81c7e8b0fc299d29ff5f1f2233725|
                                 |    |                    |af2c_2020-09-03__111206._doc_20200903_063200                                                        |
---------------------------------+----+--------------------+----------------------------------------------------------------------------------------------------+----------
339c109600ff5fb54e3f120ba565360f |33  |vba_agressive_hunt  |MALWARE_NAME: TrojanDownloader.emotet                                                               |2020-09-03
                                 |    |                    |NAME: /tmp/eml_attach_for_scan/339c109600ff5fb54e3f120ba565360f.file                                |16:27:23
                                 |    |                    |FILE_TYPE: MS Word Document                                                                         |
                                 |    |                    |TAGS: obfuscated,doc,macros,executes-dropped-file,hide-app,create-ole                               |
                                 |    |                    |NAMES: /tmp/eml_attach_for_scan/339c109600ff5fb54e3f120ba565360f.file                               |
---------------------------------+----+--------------------+----------------------------------------------------------------------------------------------------+----------
e07eb7e323630356f13dde1c7997f431 |36  |vba_agressive_hunt  |MALWARE_NAME: TrojanDownloader.emotet                                                               |2020-09-04
                                 |    |                    |NAME: 2764 WLJ 請求書送付のお願い.doc                                                                        |14:46:39
                                 |    |                    |FILE_TYPE: MS Word Document                                                                         |
                                 |    |                    |TAGS: obfuscated,macros,doc,hide-app,create-ole                                                     |
                                 |    |                    |NAMES: 2764 WLJ 請求書送付のお願い.doc                                                                       |
---------------------------------+----+--------------------+----------------------------------------------------------------------------------------------------+----------

323faa41386ee0dbabe2008e1f52db78 |38  |vba_agressive_hunt  |MALWARE_NAME: TrojanDownloader.obfuse                                                               |2020-08-21
                                 |    |                    |NAME: Contract_772.doc                                                                              |19:47:39
                                 |    |                    |FILE_TYPE: MS Word Document                                                                         |
                                 |    |                    |TAGS: enum-windows,exe-pattern,doc,macros,run-dll,download                                          |
                                 |    |                    |NAMES: Contract_772.doc                                                                             |
---------------------------------+----+--------------------+----------------------------------------------------------------------------------------------------+----------
{redacted}

```
