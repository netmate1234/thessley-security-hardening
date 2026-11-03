<?php
if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Discovers and wires up modules under includes/modules/*.
 * Each module dir has a module.php defining a class Thessley_Module_<Name>
 * with static activate(), deactivate(), register() methods.
 */
class Thessley_Module_Loader {

	/**
	 * Base64-embedded so the dashboard header has no external asset
	 * dependency to resolve a URL for, matching dashboard_styles()' own
	 * inline-CSS reasoning. Shield-and-checkmark mark supplied for the
	 * project; small enough (~12KB) that inlining costs nothing real.
	 */
	const LOGO_PNG_BASE64 = 'iVBORw0KGgoAAAANSUhEUgAAAGQAAABkCAYAAABw4pVUAAAAtGVYSWZJSSoACAAAAAYAEgEDAAEAAAABAAAAGgEFAAEAAABWAAAAGwEFAAEAAABeAAAAKAEDAAEAAAACAAAAEwIDAAEAAAABAAAAaYcEAAEAAABmAAAAAAAAAGAAAAABAAAAYAAAAAEAAAAGAACQBwAEAAAAMDIxMAGRBwAEAAAAAQIDAACgBwAEAAAAMDEwMAGgAwABAAAA//8AAAKgBAABAAAAZAAAAAOgBAABAAAAZAAAAAAAAADVwxdQAAAACXBIWXMAAA7EAAAOxAGVKw4bAAAFV2lUWHRYTUw6Y29tLmFkb2JlLnhtcAAAAAAAPD94cGFja2V0IGJlZ2luPSfvu78nIGlkPSdXNU0wTXBDZWhpSHpyZVN6TlRjemtjOWQnPz4KPHg6eG1wbWV0YSB4bWxuczp4PSdhZG9iZTpuczptZXRhLyc+CjxyZGY6UkRGIHhtbG5zOnJkZj0naHR0cDovL3d3dy53My5vcmcvMTk5OS8wMi8yMi1yZGYtc3ludGF4LW5zIyc+CgogPHJkZjpEZXNjcmlwdGlvbiByZGY6YWJvdXQ9JycKICB4bWxuczpBdHRyaWI9J2h0dHA6Ly9ucy5hdHRyaWJ1dGlvbi5jb20vYWRzLzEuMC8nPgogIDxBdHRyaWI6QWRzPgogICA8cmRmOlNlcT4KICAgIDxyZGY6bGkgcmRmOnBhcnNlVHlwZT0nUmVzb3VyY2UnPgogICAgIDxBdHRyaWI6Q3JlYXRlZD4yMDI2LTA5LTAzPC9BdHRyaWI6Q3JlYXRlZD4KICAgICA8QXR0cmliOkRhdGE+eyZxdW90O2RvYyZxdW90OzomcXVvdDtEQUhVSWtLQVYwYyZxdW90OywmcXVvdDt1c2VyJnF1b3Q7OiZxdW90O1VBQ0ozMXdMTlZnJnF1b3Q7LCZxdW90O2JyYW5kJnF1b3Q7OiZxdW90O8OJcXVpcGUgZGUgbmllbWUgY29uc2VpbCZxdW90O308L0F0dHJpYjpEYXRhPgogICAgIDxBdHRyaWI6RXh0SWQ+MjVjNDE5MDgtZmZkMy00MmUyLTliMzYtZDA4NzFkOWNhNTE5PC9BdHRyaWI6RXh0SWQ+CiAgICAgPEF0dHJpYjpGYklkPjUyNTI2NTkxNDE3OTU4MDwvQXR0cmliOkZiSWQ+CiAgICAgPEF0dHJpYjpUb3VjaFR5cGU+MjwvQXR0cmliOlRvdWNoVHlwZT4KICAgIDwvcmRmOmxpPgogICA8L3JkZjpTZXE+CiAgPC9BdHRyaWI6QWRzPgogPC9yZGY6RGVzY3JpcHRpb24+CgogPHJkZjpEZXNjcmlwdGlvbiByZGY6YWJvdXQ9JycKICB4bWxuczpkYz0naHR0cDovL3B1cmwub3JnL2RjL2VsZW1lbnRzLzEuMS8nPgogIDxkYzp0aXRsZT4KICAgPHJkZjpBbHQ+CiAgICA8cmRmOmxpIHhtbDpsYW5nPSd4LWRlZmF1bHQnPlNlY3VyaXR5IC0gNTwvcmRmOmxpPgogICA8L3JkZjpBbHQ+CiAgPC9kYzp0aXRsZT4KIDwvcmRmOkRlc2NyaXB0aW9uPgoKIDxyZGY6RGVzY3JpcHRpb24gcmRmOmFib3V0PScnCiAgeG1sbnM6cGRmPSdodHRwOi8vbnMuYWRvYmUuY29tL3BkZi8xLjMvJz4KICA8cGRmOkF1dGhvcj5uaWVtZSBjb25zZWlsPC9wZGY6QXV0aG9yPgogPC9yZGY6RGVzY3JpcHRpb24+CgogPHJkZjpEZXNjcmlwdGlvbiByZGY6YWJvdXQ9JycKICB4bWxuczp4bXA9J2h0dHA6Ly9ucy5hZG9iZS5jb20veGFwLzEuMC8nPgogIDx4bXA6Q3JlYXRvclRvb2w+Q2FudmEgZG9jPURBSFVJa0tBVjBjIHVzZXI9VUFDSjMxd0xOVmcgYnJhbmQ9w4lxdWlwZSBkZSBuaWVtZSBjb25zZWlsPC94bXA6Q3JlYXRvclRvb2w+CiA8L3JkZjpEZXNjcmlwdGlvbj4KPC9yZGY6UkRGPgo8L3g6eG1wbWV0YT4KPD94cGFja2V0IGVuZD0ncic/PhnDUhoAAB4tSURBVHic7V13eFvXdQdEyZIt24ktO8OJE6d1E6f50sRp80f75YvT5GvrtLVsyaaWV2zHqZM0cdMMS6IoUJKtWrYlWxYXBgcoapjWIEFMLnABIEhwD4DgkETtvQdFAqf33PHwMDjkyAKl4Hx6AgmCxHv3937n/M65514oFAlLWMISlrCEJSxhCUtYwhKWsIQl7FMyUCjJ/0pVV/JtKpViWrxP5y/agIGhUO1J/sLSnoVfZ0+y5xJ2o40P/B+9c+9a4U1eotrz4qx4n9INM5VKNQ0AptadB8w9rehdmLK8Z8H38Gs8z/ie1I0wfpEIyFQBpQiSk/BxpTf5j6m+BX/Cr5OL2HO3tCUD0ItMLrJ84w1D3VfY10VxvXCV/bHp+LiiO3nBCu+Cyniey400JblyeuHfyin9zgO5lmPvWx1dZfXND+BzKjv72Y22Is4CVW/ydwkzjqzwL3qUfg+3sqsibukxPuCP6ow/vCPHcvI2nQVyalpBX+H2Z1rqv4E/o6DcQBcm4sOv3U/NWb1vyR7V4KIV+L1wX7ekUXfEL/xLmtJXb9dZhhUaE9yhNgQ2WRyjW2pbILey8YTWXPcEvqaoCJJUAJ/+3SnkLckzVH2L6lcPLWmiT0+RmHb9DS+Mu6i8PPusL6hL85LyK0ChNo0qMksCd6hLIcPmhLwyZyC/silYUN0MGkvdCv7byiIeaz4tE64qrX+R+s0Dz8IbbU/fwq4KWcED9Xdzzd+/W2vsmKavAgLE6LQsQ1CRUQJ3ZRtgk9UBuWUu0NkcwdwK9+hWRydobY7yPIvrIfZnipLgU2CLCOKoptaffxlW9i9Mxe+TbzlXhYPHgQA7TH9Aa0yZmWO9osixMTCyS0GZWQKKTbtB7z8Aew4dh2xLPegIKASYoK7MObq1vgNyy90nNabqF8SfRWCulxsTYCwjiurtYy/AqsFF7sfNj89k53+rZOQqAQTzv4/kmv7lbrWxnbIi20hdVBIBQ5FeDEkZxaDv3Q/Ceg8cBY3VSZjhJEA04OMourDC2jbQWh02rdn1d/g30bdzxnziQRPBemnHU/+4amDxxbSBxZDSlfwDfO7WyDkIEDRo80F6VG/85hxNyY4ZuYQRnBWEEcHpaiMoPtwF9+VawDJ0lAIxEggC+Udt6NgpKKhspGzJq2iAnDJXgLCGsiW/ovEyiS0b0o32L+B7MGDgmoERA760Y/5fkbgx+O6pF4G4rHfkP7t5LRQj6KD867aaBz+nMWTO0pquKPMrQZFVOqrIYqyYnmUAxQc74R921IL/zAUGRjAIQXoAfUQ7feES7Ha2Q6apjjIFD3RheRXuwDZnF4J0XGd1vKErrr8L31MAMxlXJgqGv+pKvnNl70LnuhMvQlr/wnaV//G72QtuSldF7kjME5iEZUDk7n7wi5rSDberjeeU1D2VBhSZBhIrDJBEVBTGCjxed3TBpZFROvCjhBZBCBl+LUAZGQ2A0ztImaIhAT+vHNniDOrQjVU1BREYndW5T2dxvZ5u77pTnBmCMo4qU4p8Q9W/aPvaQ88BeYSUvuTH8bmbLedQKlgeMV36nti3N1u+93mdUX27pvQsA8KIymlUSRQUAjENAzdhxSPbq8Cyj7moQDBIDzH4J85dhMOnzzFQBFs4SHuJCyuqa4VMcx0N+AwY4sYIMHq7hwFT5hzUljcsy7U2PkjPjLswTC7lrBHKiTBj3Zv7nwWUuKl9izLpa28KiQucCRH1peQi+51/nW994bPqEvttWlNAAiKrZESZyYFA97RxJ9ylNcGaZj9cFKwIsngR4GAcP3sBCu1N1C0dOHEmBIqMLVdHR6G5f4iCkWWuhxzuxigwVkegwO4B6spsrnMEnM26MsdP5OUXdGmqLtVt+HWKL/mXa/YtIYpqMaQNLupb1pJ8P3vN1HRVSgqCWj1DEVFqBnKB38qz/Oh+TWn2HdmGo0n55aDIJQfmEpkhRigpELtASRRUcpkHBs5e4KxgYARlzNh/4jSWS4iCYspKZ3NB38HjHBSQXivYgrGlrMVHXVg2AiNjDCqyvIpGCoy+yoOqrENb5kpRWx2PiJm+5d1P/zRtcPGIyr8o+OYQcVe9C+fj81PPVaEbilFlRSZ8M8e44B6t8YPPqA1907XmIJWvahNgfFDSGFHKYgS6JsIIdFH/aXZD3aGTUlwIRARttO59hwkACISDqqmiuhY6wGoSMzx9QxDgsiv0u6FYc/DkGbA291AQkTE0d2HA0BiTY3MGN9e0EHA60Z2N5FlaKjfW6NPS9iQfXDWwBFbvWwzL/f+Rza4xOclObraiOFeZYxpmwo9qrQ9/Jcf0689qDR8TJpxOyrEFlQV2UGgtOOjIhhHMsKdjYsfzCYwRdxDX9FxlM7iPnpYGLhQrQjHh/KUrUNbqY66HJYFkMF1gauqCkoZOCg6qq1J3J4ktF8KCvZxdaEdI3Klq99Pfwb+HzBGqLNfmJHLZMZpX3gQF9Y2wYf+fIG0gOZDqSw6u8r0EGfaPX7MVwOwpp6rQv34xx/zKbLUxf47G2E2k6fB0ZAGrNaFLChAmXCVqKTAdYwOCkFECSgICqqaHt1bCqqZe2EMCs5wRVEHJBhC/79p7CAqqGung8TtaCtRmTzc5esBAgNhsb+SxwgWN/n0wzOPPWMCcuXgJmvxD8FFtM2GYg/4uMi+nrAHjSvCt9j+Mpvjnjqz0Lg6m9s2DjY4c0Je3k/euP6mzOUxEva0nrJoXbyTonfH7goLZ9+rLjykKa0GhsQQVbMCxzjRKWBCkWTXGBcIEAcL9+VZ4vrIFjHuPwGUiT0OMEEE7fMAOnToLxQ0dfKCcEhgCkHwSR2zNXjA2MVCQLR9xF5ZB2ILubPDICZBbULyP7Lmr5Fz2HD0JdsIaBD7P1gzvNK+BFX1Pgsq3BFL758G6tuXk+SaU0JBPEtDC2rbgzuZ+IMJg7+/Wr79dPjZxAeQXBsMd92hMexW0tmQYJbEhSAHIYHIVAzQqpq9tqYBXq9ugqP8gnLpyNWxwEITRCBDQUMqWE/eEIOCdS10JB0ICxMYAwdchICZ+WAgw6MK2VHtAjUGcxJZSdxfsOXIy7H1CMUr+3gEIkFP8qE8PS31zSfBeDCv9C2B55xLYZDOT/MUtcpogyWVG8lBY2Jy+jWbzzLgDsr7Iefu9WuM+hcaMxb6gkoPxQEEZvEIAyO7eA55jZ2BYxgQBwkggIMnXEEsCMHT8FB1QEXRzQkE36sDArq90Q2VbLxgbuyRATJwteOwiWbtwdXgUuzrAf/AYXLk6EsWakQBzb93nXbCy72kgOQcFZHnvk2DetwscHQegsLqRvi8/h0BBdQt+36VWe2bEDxBe/Muz22fN0RoHFVozSlZW+COsSO/cQy9sJBAacIwD6BYiQUA7SQJwE/H3H9e3gsbC7mgmS6NBiAQEa1f2Dn8UIHK24ONORxsFJpvGiTqav9R29VPVxeQxO6+hS34KQorvGVjlfxbe8M6F/P1rpHPt2ncoFMdI8EdFRqR3i0xpxQ8QM6EpCeZ9qKJCgOwkgAzSk7/MAYiEAJ87duY8tA0coAOJriiL+Hu50hkPiDBAyCDXdPZB6RiAyBmDjxiPttc006CfYayj7rCovhkavPvBe3QQ3ht4DZb75kOafzGs8CXDav9zcHR4SJJ6nURcZPE6GQOkFQFpkDEjfoCAB2bcpzH1CEBQzmLseL99IIohV4nawRK5o2cQdhAm6LhLUlvGd0sTAbKZAtI/ISByYJA1eCPsrG8jTEEXROSyuQZUrb+GlN55lCF4vOF9AupOlnCGM3fWvucgldZ5tGjpGsXyfo7VWSMbnLhIYQYISYru05R2KHRWBoiaAfJua78EiPBQJ4m0xbsxgzLBKYHwSYAQB8aZLdXM9UwWkHBwGEBGtxfWd64kiuopCYyl3idBN5TKQ39QcrWtA/spswQgW+ra8cYoiwcI0YCQZPB+ndETBsj7O2Bts5+xQgbIqfMXiSJq+LNBiARka40H6ro/GSDGpk6wNvVDVucHkILyFhUVCeQrexdAqnchDJzzMhcLodjX3I+A1IYAqaeAlPLxiFuiKABR3qc1OnESSZlVEpiBgGzYAWkk2ZMA4S4La0mYFaNUvR5gUEAI07aReFDfPUBl7bWCYWscgLz2AuqmVvYuCqkq/5PwgecDuHiRKzAIFTRRfGRILotNFZMbY8eUAATtfq2xWpFThgwZncEZktroiwLk7MXLNGe43oBghl1P4tK1AEKZQcDY2mqA1N5kcizggCyCFf6nYW33b0Bf1QAXLl+VABG5itu3V4ohJJMf2eboxMdCHAuV6ga0HU1kc3QmC63cksRQuKw/urpDMYQDcv7yFQ6I87oBgrEIM3HHNQCCYFia+mBHcw2k+Z6ngKg4O+hBksBCjwm2VLbBpeHhKECc5L3CAKFzKg4djkWci4yMnvdojLsVeeGAvF7fxZSJTPJevDJMk7jrC4iDTkA5vXvAQAAxTwgGvsYHBk8LrPX+Elb0zpfAYK5qLokn74PR5YcCu1uqg4EMEBQQmMfQqWECyHZy85GMPZ0B8un2gI1vfM7jMxrjFlpMFIAQlfVaTXsUIJgZYxJ3vQHBZNJFAemcABAEA3ORHniveymk+ENBXMVd1Vve16DU006y+U6q3nByKwQIe6wmOY9IDBGQjxpoVeFdOiRx6itmlszoeZfaoFFghTerZEQA8pK9jakTGSCYh2ASp71OgORyQDCnafBNDhBLYx982LU2DAwJkN6naUyxNQ3ATmcrbCexaSSi5IOGZZpsqeLsvFpEJDNhyGocC6l8Ehfj7Z0z1cb3FDjnkVkyIjL1JeXNUYCMkLtti73p+gPiaCOA7B0XEKGotB1qAsZTEWAspgBt6lxHAn0/yUu6aJkFmTcaiAbE1uKlpR3JZTGGLIs/IDhVi5ZVkqbYXIMu66qoZc2zNoaCoQCEXBzedaiMIqu2fw4gOHgNvWMDIhRVQdvHxC3NDwVvejBmvOl7FUo8zWBq9JIsvpuCgUXJWHU3fA81BcRFZS+qLJ3F8ToOhT2uLosDMivboFLKAflwFzxubAj5Xv6I06roXjS8D/e6AeJsA/cYgDAw+uGjljLOimQp3wgBMh82t+6gr6MKjGTuKBTw70UaXksJeZ5OB5S5pEw9t8z5cxyL+MYQDsh9GsOKpM3VIZf14W54rMQRBQiqFCzsaejcxlgD7eTH5AHZRQHZFwUIKioLSVB3e1ywxvcyZYJc3gpXtbFzDY0tGGNodbi5hzC5hf6tSEPG4A0gu6kCm6tb8JoW41jEV2Xxu+FLOuMb0zezGEKnaDfthu/vqJXoLic9FvTEZFM4CDhl6oZcWyM9Qs9PBpB2aIwCBBWVF0qb2mFdz+vEVc0LixvIjNTeZ2C17yUCmJtKYQGItdlLs3/sUIk0jCmY9+D70vOwOYP5VU2QbRNrUuKYh4iVTA/nml6fIZYIZLPp2r/dbidZeiAKELxYERDFoOfa3JBnbQZdeR2oqyygqawAnM/Os7aMC0wYIH45IGxgzY298H7XyihFxY7FtFyib9tK4wu6KsEsPEecacQGiMjzp8KkWhImQXoe2Nhtcf0o/oCIdX75lp/P4ImhAOSrheVweXQ06oIiJCNlg6bCDu81vguru18BlW8xOZ6FNzt/AxudGsyEKWCxQBGA7Ha10/qSAARdlSgYLo8BBnNVT8GG7lTq0gSAckCwpI8FS+FqhQ1fHZXnUsFcXmDMtTjZ0ucbsWJrLBMrXv++wJI8I8fKOkz4FO69uRY4z6dIWdmBXVAoy3VRMNRVNgLEq5DSN5cM1jO0ykorrUQNYXPB2rY/gbailrsxx4SAmDxM3ua26cmgzwsviUiuKpmWTHZ5HAQQX0xA8ivdVLmJuDFG+QcXB+HjFaIcH6aAxHUtugCk0PrPdJkAAUPJOhFhttYERy/xOpCsyQ0TuFAdyA1r239PB35l75Io9YN3Mv7szY7fElDsBJSmMKaEAdK3j6ifdgpGdMEwmh057fnEVQ2GuSo5IHh+LQP7Q4DIphB42R3PJZiHbClznd9U7p6DYwFxXVfI74ZHNKavT8s0DNPOEw7ITI1RWjIgGt7Q6OSOqQbyy1ogvW4bYcLTUYMWfiyhk0Zrun5FY0ue1SMxJQRIBzT27QFjQy/sbKmBVbEKhjIw1ncv5a4qdhKJsjefDLp36IjkssQNhZ0w4obQ8YCuszmOFNhss+MPCH/zezea756WZTiLjXEUEMIUjCWNvAtRDkjP0GHismpBb2uD9SRusJ6nyIAbeSBT5sHqrv+iLk6AkksCPwOkDTz+A7DL3RRVMJQzDl2higCMVV5Lo5/GmrFAQbeEPVqRgOw7doomthyUAC4wJcB0qz1x7TgJB+SxIvuds9WlJxggJawvi7DENnSMSUV5g/Tx06wflyiodz1vMXc1ISAClPmwqudlyLabqCrLKXeA2lpPC4HYz/t2xx+iyiJydmCA13ZoolRVVGZPpDkCcvj02ShAsH1IHcqj6Hy6zuaqlo1KPFtLZa1AGuMe2ptFArvIRTbz9X8jESX4/EribiytsMG9kcePyQDCAzJxcat6fgZZ1aWQZ8N8oA521XeDfvB9WOp7AtLGAAMD/Ds9/0srvRM1QJSQ5BWVFJ6rECWC4e2DB2QNDs7RrY4OjCXbcRymwuYy0t0wRzZryCq+O2CNh03jyjtP8E7DIKw1uyG7xsBV1WTACDEl1f8MqLzPQ0bNDsg3d8EHTR+SxC82M8T8+ErfIviopWJCV4VZOrah4jmGdTjGmC0UpXeSHH6AYxDfsokwnovcrjGuUxRUh1V8F5d5pBgiv6jargFyUbU0sL/XtA5S+p+Qpk+vhSlpPS+S338nNOgxXitclbojnSqw8VyVUFh6wo6arvAcRECDyWLUXIi1PgXHIL6VXm4iW/9ajun3MwrYnAh1Wem74dsfVUvskNPeu/+ILDlsIMH9PTrAeOdfm/taQIP9WK9hk07z4W3vbzgQPVE5R5TLIgfmGHiOckDEjRVZx8KgrrW6FuIYxLeOJYznIt+JkYvcqTPD4YtXJEDEpV24PBw2c4gBPr1uO4kNr/ABXjxJtkzMKqxXbWuxSJXc8cCw8D5gnGaWxw9hF69clU9BB1nzd8NVfVnzN3EMpkIMkZTWN3TFd83MMpwRSotl7MVQsvewpLTkZmvxcZawWhWqJk1FFfxf6zKad2CjweRd2Fiuai5kdG4grmpiMCR3RdQVrq6Sm2AJymCpqEjYobd7cKZwEEWNfCzibdJJ3KMx1dBF/lmhufVlbq+ktOQX149bYZjlRUYHrVlhNv6+K0OKE5N3YZGuis+PN7XRqu+Eroqwo5RXogcOHw87V/GIBczobhO3Hq9dFc8aVpTxeZE7NQbVND4vIqTv9z6ukdgRtgJD7o/L5WV4ZEsrZFYXk+z8NS6LryXgM1eGyeGW1pIJcw45OwpJ1o3nFMtwcg3dmYgfYmKK5FS/wGufGgpLGI8jD+XbfpikMYXiCHlMIkfzsTMSCPI7rvfgUamdJrySSxJHm4eW49c1r4JUkhCm+pMnxZbQ/PjbBAycdJoYDLEUDhnbd+hYTHYcOXOO169cofhR3nBJY2v4Gl771IgfkvGMPS9v1u3q0n66wFPWeC01zcWYnzYRNxE+PxJii5gn2ejIJXnHczRTHx8UZMYz0vz4ZFyVyD2QpZihR5oAxOXbIy1BEOzIq2i0xXvkxzaej8xWG96iq26p/GVzIw8WlMPp4VBLJrtQ9ogrZZmmj9X4wGYSUYXhxNVbHf/DAr6ksGKwg7gqbGaYjKoSYGyrbabncPr8pbBzE3aZnPvWao/ULUPONbClvgPzkJ+xS59K7koYp+wDGuN3SWI4QutZuBkAXy/yYQdbwBOZtaN104JjLJa4ZAG/iU5WYSIYnrMs4ssHlsAy/xOwsSt8fnwimYsdK+g2fQeOhp2T/GtcDxJKBp1BVFdE7u7daG6gG87AFFFX0cZPbKbOWqzIq+AziGwt+t8UVsA52YRV5EXjRjGSghmz+aGB5yxbIc37EmHLXOrGMHdZ1jsX1vX8DgyTdFUIBtsxqJZ2rESCIQy7LXF+XSvEh2gdLWugjXFTIxkcy3hwvzvX8m/TdFa2UQAGdl5KEYt4InMSMRhYlpgYFAfLWSorSIa/Hta2LoV321fClu6ttKHBHGMGMCYziJrC95JKJGPEDqwih/p42YRUXoX7WK61hm5UM3XZIYyf4Ayt2SoasJXZbFr3vhwz9J8NTVpFg8L6ZnGg2AYxY3WcOOiULrJFZ22AbfY2cHQeJEG5e3ww+KpcbNbDFVC1fM481s2BJhYY6fgsJe6Hst2F6yEbVHiNU3I7jSjj6yNmZpX+SEl3cpCzZBfMtbjHZIkwnI5F5RW5SUAsttA1hvZGqOrwjbkK18xZgdIW5znwb+Ni07HclHjG5OmWklcM5Fi30ld6vOqi8s/gNU59dgjjoCizSwsUrD1oRA7KOy199IJjyWAxQAOHT9DODxFMJ1qnXkHXqccGAoHCxjf8W9jCg7N+Y4IhrZIaihQadLWtrqx+Ll7b1I4dkSbunI07v6zQWPayvKSEdqTQI6MYSvcemRAU7PDAtiEsZ6jHWC4tdnIoaxVbazAQzBwIbGpDpiEr0B1eEvJ7nPfFsg6+p+w9RtjWgA0Z7PKmUplksib8a8bup3BBKNs70cA3nymGOToztJ5gU6RyKRw5OGi4HQbKU3XYhgINvNnZRdctYj6BYGA9Cl+LmwKoyR2OLgcnmw4cD+0yFMtZiph2+NTZUF7EdzYtrGsDEsyb04vsdCtAuGlcVaQJUNTG9WK5ggQKkcJfyrdB58lz44IS2g0oAHuPnqR3Pw5WJl9aLXYDwkCNIODPcIUssgJbQXEOX14GiRW6BBhHz5wDPV+/IuJGfmUT5Fd5TmVZ676Dl3JzsiNkSlpWwQ3Osg1lCn1lFCifz7WC4zDz6fK593Bgwr/Hfa4wb0F3hIAgOAIEXCuCecVxrubGY4V80gy3l0VFRZdKIDOsDqxXBfVVnkCWsf5JvJibQ1VNZKLolrnzc4psYxtLGMNBmU0edwwcYkyQtQzFZkzoe2QNgoOZNG53cfzM+bDfjdwXKxJk8aPeA8comHJm4JaymJETN/k8nv7NFcQnMkFzDPLZhh6WnxRLoEzjW4anNHolOTwyhnuZaKAnA4QATWwlK9/ag7mpRrrEQG12vIynHd9FOJ+WCbpn7X5IkV3qY4tEKVOCmDgm8U2Sf2JwwsBZtlpf2vhyzKEPDXCsDW5iAsW/xt2H6KZoplD5X8u2jgW9vfmqxuSk+8VPzcLh9TKxqH5T8QOEKW6xUFQ0aYvVV5/VmWBti1+qfVFgAhMPeGwUwoHAyi3GGFRoyAzepxtEaUs3769wH9Wa6v4FT/PT/piLqWEClHXFdxFJXEhjitYcwLUl1IXJNk9+qLAC9L79YXFhvBgTxQbZ63B9I8YZXHSaaQ5zUaP48Ra0YGhz1eoqHV+lpxna8PkvwOgHtHBg0kt+RoL9KbHOnSaQfHtxJe5YShjz/Z11tAvyzHD41oAYZ+QuLVbsuDg8DF37DlP1hUVCWTkmwCaa2lDWjmot9W8XdXXRzZJvDTV1rYagyONKxm6LAjff11qCnC20JVXMzWPJ5cuby2GF2wue42fGdV/IoEMnz9DdHUT5RWyMlsM3TS6obg5uqaObxjhyrY5/wtOgny0yFfYqiatJdyMBKHP3LwgYQ2HAZJZQYMRnhqArm04Y9INiB6QQcKoOHocDFy6T2DBCE0dcr05bVW2OyF1MJSDYRvyOQZJYviAA+HM/T+TWMsxVhDROL7qTSOLfkmMvDfo5NqwWB3gnC91CkPZ8IWtw11NcrZVjBg1f1UQ3R7NI60eCOKGE8xgFNS1B3KmaANVPkr//Fus5VMA/tyRhkcZdmLhLMehnGn6tyCjuUGItTF8VVLCOlgBfDx+YkV2KLArOIgBtsjiCeWwRZpAAcRUZgYtpCBuCetruWd+LQKgNnjvou/FP2ZkqzW1T10KxhQ0UUTtJ6bv/XZlZoifHMWWOFWgTBe5gxzdpnkXAycC5bsISHHyimIKFNa24D+JBXZlTTVjyU/meugn39EksEhi0zC333KY2PJWUVfzedLWhQ8mW0QXv1ldAZllDIM/mHCbuqVdb5krXWV1Pi4kkYQkgrpfJPjpPGHbdz0rf8dWvaEw/flRvfnmDqebH22oaH1QVFd0W/qtFSTzBSwBx3U18wOQESRuVrzf4o1cTBvzDY4hsfYwAlMzdESSYkLCEJSxhCUtYwhKWsITdDPb/D+d8y6SEZ48AAAAASUVORK5CYII=';

	private static function logo_data_uri() {
		return 'data:image/png;base64,' . self::LOGO_PNG_BASE64;
	}

	/** @var array<string,string> module directory name => class name, in load order */
	/**
	 * Order here drives both activation sequence and admin-menu position
	 * (register()/activate() run in this order, and each module's own
	 * add_submenu_page() call happens in that same sequence) — so this
	 * list is grouped into rough categories for the sidebar, not just
	 * build order. The one hard constraint: vuln-scanner must stay ahead
	 * of auto-update, since "update what was flagged" mode reads the
	 * scanner's last result. Everything else here is free to reorder.
	 */
	private static $modules = array(
		// Overview — read/audit views over the shared events table.
		// event-log first: it owns that table.
		'event-log'       => 'Thessley_Module_Event_Log',
		'geo-map'         => 'Thessley_Module_Geo_Map',
		'activity-log'    => 'Thessley_Module_Activity_Log',
		'bot-log'         => 'Thessley_Module_Bot_Log',

		// Perimeter — blocks by IP/identity before WordPress finishes loading.
		'ip-blocklist'    => 'Thessley_Module_IP_Blocklist',
		'whitelist'       => 'Thessley_Module_Whitelist',
		'geo-blocker'     => 'Thessley_Module_Geo_Blocker',
		// geo-login right after geo-blocker: it reuses that module's
		// compiled country dataset and class, so must load after it.
		'geo-login'       => 'Thessley_Module_Geo_Login',
		'rate-limiter'    => 'Thessley_Module_Rate_Limiter',

		// Request inspection — looks at what a request is doing, not just who it's from.
		'query-guard'     => 'Thessley_Module_Query_Guard',
		'login-guard'     => 'Thessley_Module_Login_Guard',

		// Integrity & detection — is anything already wrong.
		'file-integrity'  => 'Thessley_Module_File_Integrity',
		'malware-scanner' => 'Thessley_Module_Malware_Scanner',
		'vuln-scanner'    => 'Thessley_Module_Vuln_Scanner',
		'user-watchdog'   => 'Thessley_Module_User_Watchdog',

		// Hardening — reduces what an attacker can do after getting in.
		'headers'         => 'Thessley_Module_Headers',
		'user-enum'       => 'Thessley_Module_User_Enum',
		'hardening'       => 'Thessley_Module_Hardening',

		// Ops — keeping the above current and knowing when it fires.
		'auto-update'     => 'Thessley_Module_Auto_Update',
		'alerts'          => 'Thessley_Module_Alerts',
		'ip-sharing'      => 'Thessley_Module_IP_Sharing',
		'scan-all'        => 'Thessley_Module_Scan_All',
		'config-io'       => 'Thessley_Module_Config_IO',
	);

	/**
	 * Shared WP_Filesystem instance for the local, plugin-managed file
	 * writes every module does (compiled datasets, mu-plugin sync, the
	 * local blocklist cache) — never user uploads or anything reachable
	 * from a public request. Only for admin-post/cron/activation-context
	 * callers: it requires wp-admin/includes/file.php and, on the rare
	 * host without direct filesystem access, can need credentials — both
	 * fine for those contexts, but wrong for the early-gate check.php
	 * files, which run pre-bootstrap on every front-end request and stay
	 * on raw fopen()/fread() for that reason (documented at each site).
	 */
	public static function filesystem() {
		global $wp_filesystem;
		if ( ! $wp_filesystem ) {
			require_once ABSPATH . 'wp-admin/includes/file.php';
			// On a host without direct filesystem access, WP_Filesystem()
			// can fail without valid stored credentials rather than prompt
			// for them — there's no admin present to answer a credentials
			// form during activation/cron. $wp_filesystem then stays unset,
			// so every fs_*() helper below must (and does) treat a falsy
			// self::filesystem() as "can't write right now", not fatal.
			WP_Filesystem();
		}
		return $wp_filesystem;
	}

	/**
	 * Every raw filesystem write in this plugin goes through one of these
	 * instead of calling self::filesystem()->method() directly, so a host
	 * where WP_Filesystem() can't initialize (see the docblock above)
	 * degrades to a no-op everywhere rather than a fatal "call to a member
	 * function on bool" on whichever call site happened to run first —
	 * exactly what broke activation on such hosts before this existed.
	 */
	public static function fs_copy( $source, $destination, $overwrite = false ) {
		$fs = self::filesystem();
		// Writability is checked up front, not left to WP_Filesystem: its
		// direct driver emits a PHP warning on a failed write, and a
		// read-only target dir is an expected condition on locked-down
		// hosts, not an error.
		return ( $fs && wp_is_writable( dirname( $destination ) ) ) ? $fs->copy( $source, $destination, $overwrite ) : false;
	}

	public static function fs_delete( $path, $recursive = false ) {
		$fs = self::filesystem();
		return ( $fs && wp_is_writable( dirname( $path ) ) ) ? $fs->delete( $path, $recursive ) : false;
	}

	public static function fs_move( $source, $destination, $overwrite = false ) {
		$fs = self::filesystem();
		return ( $fs && wp_is_writable( dirname( $destination ) ) ) ? $fs->move( $source, $destination, $overwrite ) : false;
	}

	public static function fs_put_contents( $path, $contents, $mode = false ) {
		$fs = self::filesystem();
		return ( $fs && wp_is_writable( dirname( $path ) ) ) ? $fs->put_contents( $path, $contents, $mode ) : false;
	}

	/**
	 * Two independently-gated one-time upgrades chained together, one per
	 * historical rename this plugin has gone through: the original
	 * prefix -> `shieldcore_` -> `thessley_` (current). Each stage only touches
	 * identifiers still under its own specific old prefix and is gated on
	 * its own "done" flag, so a site is migrated exactly as many stages as
	 * it actually needs regardless of which historical name it started
	 * from — one already on `shieldcore_` skips stage 1 entirely (its old
	 * table/option names don't exist to find) and only runs stage 2; a
	 * still-unmigrated legacy site runs both, back to back, in the same
	 * request. Table names are renamed in place (RENAME TABLE) rather than
	 * copied, so existing rows survive without a copy/drop step; options are
	 * renamed the same way via a single UPDATE rather than read/write per
	 * key, since a plain string substitution on option_name is equivalent
	 * and touches the DB once.
	 */
	private static function migrate_legacy_identifiers() {
		// 'shieldcore_legacy_migrated' is not a typo of the current prefix:
		// it's the literal flag name this stage has used since the original
		// legacy-prefix rename, and every already-migrated site
		// already has it set to 1 — reusing it (rather than a fresh flag
		// name) is what lets this stage correctly no-op on those sites
		// instead of re-running against tables/options that no longer
		// exist under their old names.
		self::migrate_identifier_prefix( 'shieldcore_legacy_migrated', 'wpopsec_', 'shieldcore_', 'wp-opsec-early.php', 'wp-opsec-checks' );
		self::migrate_identifier_prefix( 'thessley_legacy_migrated', 'shieldcore_', 'thessley_', 'wp-shieldcore-early.php', 'wp-shieldcore-checks' );
	}

	/**
	 * One rename stage: $old_prefix -> $new_prefix across the three custom
	 * tables, every option, and the previous mu-plugin deploy left under
	 * its old filename. $done_flag is itself written under the *new*
	 * prefix implicitly by being a literal option name distinct per stage,
	 * so it survives being swept up by this same stage's own option-rename
	 * query if it were ever named with the old prefix — it never is.
	 */
	private static function migrate_identifier_prefix( $done_flag, $old_prefix, $new_prefix, $legacy_mu_filename, $legacy_checks_dirname ) {
		if ( get_option( $done_flag ) ) {
			return;
		}

		global $wpdb;

		$table_renames = array(
			$wpdb->prefix . $old_prefix . 'events'   => $wpdb->prefix . $new_prefix . 'events',
			$wpdb->prefix . $old_prefix . 'baseline' => $wpdb->prefix . $new_prefix . 'baseline',
			$wpdb->prefix . $old_prefix . 'bot_log'  => $wpdb->prefix . $new_prefix . 'bot_log',
		);
		// phpcs:disable WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching, WordPress.DB.PreparedSQL.NotPrepared, WordPress.DB.PreparedSQL.InterpolatedNotPrepared, PluginCheck.Security.DirectDB.UnescapedDBParameter -- one-time migration, not a per-request lookup worth caching; $old_table/$new_table are built from $wpdb->prefix plus fixed literals ($old_prefix/$new_prefix, both hardcoded call-site strings, never user input), and RENAME TABLE can't use placeholders for identifiers anyway.
		foreach ( $table_renames as $old_table => $new_table ) {
			$old_exists = $wpdb->get_var( $wpdb->prepare( 'SHOW TABLES LIKE %s', $old_table ) ) === $old_table;
			$new_exists = $wpdb->get_var( $wpdb->prepare( 'SHOW TABLES LIKE %s', $new_table ) ) === $new_table;
			if ( $old_exists && ! $new_exists ) {
				$wpdb->query( "RENAME TABLE `{$old_table}` TO `{$new_table}`" );
			}
		}

		$wpdb->query(
			$wpdb->prepare(
				"UPDATE {$wpdb->options} SET option_name = REPLACE(option_name, %s, %s) WHERE option_name LIKE %s",
				$old_prefix,
				$new_prefix,
				$wpdb->esc_like( $old_prefix ) . '%'
			)
		);
		// phpcs:enable WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching, WordPress.DB.PreparedSQL.NotPrepared, WordPress.DB.PreparedSQL.InterpolatedNotPrepared, PluginCheck.Security.DirectDB.UnescapedDBParameter

		// The old-named mu-plugin file and its checks dir are a separate file
		// on disk from the current one (WPMU_PLUGIN_DIR . "/{$legacy_mu_filename}"
		// vs THESSLEY_MU_DEST) — deploying the renamed code and reactivating
		// copies the new file in but never touches the old one under its old
		// name, so both get loaded by WordPress every request until this runs.
		// The old file's own gate logic then executes a second time and
		// queries the just-renamed tables under their old names, which no
		// longer exist. self::filesystem() is fine to use here (unlike the
		// early-gate check.php files it explicitly excludes): this runs on
		// plugins_loaded, well after WordPress itself has fully bootstrapped,
		// not pre-bootstrap on every front-end request.
		$legacy_mu_file = WPMU_PLUGIN_DIR . '/' . $legacy_mu_filename;
		if ( file_exists( $legacy_mu_file ) ) {
			self::fs_delete( $legacy_mu_file );
		}
		$legacy_checks_dir = WPMU_PLUGIN_DIR . '/' . $legacy_checks_dirname;
		if ( is_dir( $legacy_checks_dir ) ) {
			// The checks dir holds two different kinds of files: the check.php
			// templates (re-deployed fresh into the new dir by each module's own
			// deploy_check_file(), already stale here and fine to discard) and a
			// data/ subdirectory of compiled runtime state (geo-blocker's country
			// index, ip-blocklist's compiled ranges, etc.) that nothing
			// regenerates on its own — several modules now require an explicit
			// admin action before they'll ever refetch, so simply deleting this
			// wholesale silently destroys real data with no way back. Move data/
			// forward into the new checks dir first; only what's left after that
			// (the stale check.php files) gets deleted.
			$legacy_data_dir = $legacy_checks_dir . '/data';
			if ( is_dir( $legacy_data_dir ) ) {
				$new_data_dir = THESSLEY_CHECKS_DIR . '/data';
				if ( ! file_exists( THESSLEY_CHECKS_DIR ) ) {
					wp_mkdir_p( THESSLEY_CHECKS_DIR );
				}
				if ( ! file_exists( $new_data_dir ) ) {
					self::fs_move( $legacy_data_dir, $new_data_dir, true );
				}
			}
			self::fs_delete( $legacy_checks_dir, true );
		}

		update_option( $done_flag, 1 );
	}

	public static function init() {
		self::migrate_legacy_identifiers();
		self::sync_plugin_folder();
		self::ensure_mu_loader_current();
		self::migrate_data_to_uploads();

		// The mu-plugin WordPress loaded this request is whatever was on disk
		// when the request started. Right after a plugin update that's the
		// *previous* version, so helpers the new module code calls may not be
		// defined yet — the copy above only fixes the next request. Load the
		// fresh file now if anything is missing.
		if ( ! function_exists( 'thessley_log_event' ) ) {
			self::load_helpers();
		}

		add_action( 'admin_menu', array( __CLASS__, 'admin_menu' ), 5 );
		add_action( 'admin_notices', array( __CLASS__, 'maybe_notice_mu_loader_missing' ) );
		add_action( 'admin_enqueue_scripts', array( __CLASS__, 'enqueue_assets' ) );
		Thessley_Menu_Router::register();

		foreach ( self::$modules as $module => $class ) {
			self::load_module( $module );
			if ( method_exists( $class, 'register' ) ) {
				call_user_func( array( $class, 'register' ) );
			}
		}
	}

	public static function activate() {
		self::migrate_legacy_identifiers();
		self::sync_plugin_folder();
		self::copy_mu_loader();

		// Guarantee the shared helpers (thessley_local_blocklist_add() etc.)
		// are defined in *this* process before module activate() hooks run.
		// Normal bootstrap loads this file as an actual mu-plugin before
		// plugins_loaded fires, but on a fresh/re-activation the file may
		// not have existed yet when that happened this same request. If
		// copy_mu_loader() couldn't write it (a host where WP_Filesystem
		// can't initialize or the directory isn't writable), load_helpers()
		// falls back to the copy shipped inside this plugin instead of
		// fataling on a missing file.
		self::load_helpers();

		foreach ( self::$modules as $module => $class ) {
			self::load_module( $module );
			if ( method_exists( $class, 'activate' ) ) {
				call_user_func( array( $class, 'activate' ) );
			}
		}
	}

	public static function deactivate() {
		foreach ( self::$modules as $module => $class ) {
			self::load_module( $module );
			if ( method_exists( $class, 'deactivate' ) ) {
				call_user_func( array( $class, 'deactivate' ) );
			}
		}

		self::remove_mu_loader();
	}

	public static function admin_menu() {
		add_menu_page(
			'Thessley Security Hardening',
			'Thessley Security Hardening',
			'manage_options',
			'wp-thessley',
			array( __CLASS__, 'render_dashboard' ),
			'dashicons-shield'
		);
	}

	/**
	 * Every Thessley Security Hardening admin page's hook suffix contains "wp-thessley" — the
	 * top-level page is "toplevel_page_wp-thessley", every cluster submenu
	 * (registered by Thessley_Menu_Router against the "wp-thessley" parent) is
	 * "wp-thessley_page_wp-thessley-<cluster>". Enqueued unconditionally across
	 * all of them, one bundle covering every module's admin UI, rather than
	 * detecting which of the tabs within a cluster page is active: none of
	 * this CSS varies by request, and the combined size is trivial.
	 *
	 * Must run at admin_enqueue_scripts — by the time a page's own render
	 * callback runs, wp-admin has already printed admin_print_styles() into
	 * <head>, so a style enqueued any later would silently never appear.
	 */
	public static function enqueue_assets( $hook ) {
		if ( false === strpos( (string) $hook, 'wp-thessley' ) ) {
			return;
		}
		wp_enqueue_style( 'thessley-admin', THESSLEY_PLUGIN_URL . 'assets/admin.css', array(), self::asset_version( 'admin.css' ) );
		wp_enqueue_style( 'thessley-dashboard', THESSLEY_PLUGIN_URL . 'assets/dashboard.css', array( 'thessley-admin' ), self::asset_version( 'dashboard.css' ) );
		wp_enqueue_style( 'thessley-geo-map', THESSLEY_PLUGIN_URL . 'assets/geo-map.css', array(), self::asset_version( 'geo-map.css' ) );
	}

	/**
	 * Cache-busts a static asset by its own file-modified time rather than
	 * the plugin version: editing a single CSS file previously required
	 * also bumping THESSLEY_VERSION or browsers kept serving the old
	 * cached copy under the unchanged `?ver=` query string.
	 */
	private static function asset_version( $relative_path ) {
		$path = THESSLEY_PLUGIN_DIR . 'assets/' . $relative_path;
		$mtime = file_exists( $path ) ? filemtime( $path ) : false;
		return $mtime ? (string) $mtime : THESSLEY_VERSION;
	}

	/**
	 * Module status cards. Each entry describes one module's current posture:
	 * `level` drives the colour (good / warn / bad / off) and is what the
	 * overall score is computed from.
	 */
	private static function status_cards() {
		$ip_mode  = get_option( 'thessley_ip_blocklist_mode', 'log' );
		$qg_mode  = get_option( 'thessley_query_guard_mode', 'log' );
		$lg_on    = (bool) get_option( 'thessley_login_guard_enabled', true );
		$headers  = class_exists( 'Thessley_Module_Headers' ) ? Thessley_Module_Headers::build() : array();
		$ue_on    = (bool) get_option( 'thessley_user_enum_block_author_scan', true );
		$fi_base  = (int) get_option( 'thessley_integrity_baseline_at', 0 );
		$vuln     = get_option( 'thessley_vuln_last_result', array() );
		$au_plug  = get_option( 'thessley_auto_update_plugins', 'flagged' );
		$uw_alert = count( (array) get_option( 'thessley_user_watchdog_alerts', array() ) );
		$hidden   = count( (array) ( get_option( 'thessley_hardening_hidden_result', array() )['hidden'] ?? array() ) );
		$editor   = defined( 'DISALLOW_FILE_EDIT' ) && DISALLOW_FILE_EDIT;

		$vuln_findings = count( (array) ( $vuln['findings'] ?? array() ) );
		$integrity     = self::integrity_issue_count();

		$mal_last     = get_option( 'thessley_malware_last_result', array() );
		$mal_findings = count( (array) ( $mal_last['findings'] ?? array() ) );
		$geo_stats    = get_option( 'thessley_geo_stats', array() );
		$geo_selected = count( (array) get_option( 'thessley_geo_countries', array() ) );
		$geo_enforce  = get_option( 'thessley_geo_enforce_mode', 'log' );
		$gl_selected  = count( (array) get_option( 'thessley_geo_login_countries', array() ) );
		$gl_enforce   = get_option( 'thessley_geo_login_enforce_mode', 'log' );
		$al_count     = count( (array) get_option( 'thessley_activity_categories', array( 'content', 'plugins_themes', 'settings' ) ) );
		$rl_on        = (bool) get_option( 'thessley_ratelimit_enabled', true );
		$rl_mode      = get_option( 'thessley_ratelimit_mode', 'log' );

		return array(
			array(
				'key'   => 'ip-blocklist',
				'title' => 'IP Blocklist',
				'icon'  => 'shield-alt',
				'state' => 'block' === $ip_mode ? 'Blocking' : 'Log only',
				'level' => 'block' === $ip_mode ? 'good' : 'warn',
				'note'  => sprintf(
					'%s ranges loaded',
					number_format_i18n( (int) ( get_option( 'thessley_ip_blocklist_stats', array() )['count_merged'] ?? 0 ) )
				),
			),
			array(
				'key'   => 'query-guard',
				'title' => 'Query Guard',
				'icon'  => 'filter',
				'state' => 'block' === $qg_mode ? 'Blocking' : 'Log only',
				'level' => 'block' === $qg_mode ? 'good' : 'warn',
				'note'  => get_option( 'thessley_query_guard_scan_post', true ) ? 'GET + POST scanning' : 'GET only',
			),
			array(
				'key'   => 'login-guard',
				'title' => 'Login Guard',
				'icon'  => 'lock',
				'state' => $lg_on ? 'Enabled' : 'Disabled',
				'level' => $lg_on ? 'good' : 'bad',
				'note'  => sprintf(
					'%d fails / %d min',
					(int) get_option( 'thessley_login_guard_max_fails', 8 ),
					(int) get_option( 'thessley_login_guard_window_min', 15 )
				),
			),
			array(
				'key'   => 'headers',
				'title' => 'Security Headers',
				'icon'  => 'shield',
				'state' => $headers ? sprintf( '%d active', count( $headers ) ) : 'None',
				'level' => $headers ? 'good' : 'bad',
				'note'  => isset( $headers['Strict-Transport-Security'] ) ? 'HSTS on' : 'HSTS off',
			),
			array(
				'key'   => 'user-enum',
				'title' => 'User Enumeration',
				'icon'  => 'hidden',
				'state' => $ue_on ? 'Protected' : 'Open',
				'level' => $ue_on ? 'good' : 'bad',
				'note'  => get_option( 'thessley_user_enum_block_rest_users', true ) ? 'REST users locked' : 'REST users public',
			),
			array(
				'key'   => 'file-integrity',
				'title' => 'File Integrity',
				'icon'  => 'media-code',
				'state' => $integrity > 0 ? sprintf( '%d change(s)', $integrity ) : ( $fi_base ? 'Clean' : 'No baseline' ),
				'level' => $integrity > 0 ? 'bad' : ( $fi_base ? 'good' : 'warn' ),
				'note'  => $fi_base ? sprintf( 'baseline %s', date_i18n( 'M j', $fi_base ) ) : 'take a baseline',
			),
			array(
				'key'   => 'vuln-scanner',
				'title' => 'Vulnerability Scan',
				'icon'  => 'search',
				'state' => $vuln ? ( $vuln_findings ? sprintf( '%d flagged', $vuln_findings ) : 'Clean' ) : 'Not run',
				'level' => $vuln ? ( $vuln_findings ? 'bad' : 'good' ) : 'warn',
				'note'  => $vuln ? sprintf( '%d components checked', (int) ( $vuln['scanned_count'] ?? 0 ) ) : 'never scanned',
			),
			array(
				'key'   => 'auto-update',
				'title' => 'Auto Updates',
				'icon'  => 'update',
				'state' => 'off' === $au_plug ? 'Plugins off' : ( 'all' === $au_plug ? 'All plugins' : 'Flagged only' ),
				'level' => 'off' === $au_plug ? 'warn' : 'good',
				'note'  => sprintf( 'core: %s', get_option( 'thessley_auto_update_core', 'minor' ) ),
			),
			array(
				'key'   => 'user-watchdog',
				'title' => 'User Watchdog',
				'icon'  => 'admin-users',
				'state' => $uw_alert ? sprintf( '%d alert(s)', $uw_alert ) : 'Clear',
				'level' => $uw_alert ? 'bad' : 'good',
				'note'  => sprintf(
					'%d privileged account(s)',
					count( (array) get_option( 'thessley_user_watchdog_snapshot', array() ) )
				),
			),
			array(
				'key'   => 'hardening',
				'title' => 'Hardening',
				'icon'  => 'admin-tools',
				'state' => $hidden ? sprintf( '%d hidden plugin(s)', $hidden ) : ( $editor ? 'Editor off' : 'Editor on' ),
				'level' => $hidden ? 'bad' : ( $editor ? 'good' : 'warn' ),
				'note'  => class_exists( 'Thessley_Module_Hardening' ) && Thessley_Module_Hardening::uploads_guard_active()
					? 'uploads guarded'
					: 'uploads unguarded',
			),
			array(
				'key'   => 'alerts',
				'title' => 'Alerts',
				'icon'  => 'testimonial',
				'state' => self::alerts_ready_count() ? sprintf( '%d channel(s)', self::alerts_ready_count() ) : ( self::alerts_any_enabled() ? 'Needs setup' : 'Disabled' ),
				'level' => self::alerts_ready_count() ? 'good' : 'warn',
				'note'  => self::alerts_channel_summary(),
			),
			array(
				'key'   => 'ip-sharing',
				'title' => 'IP Sharing',
				'icon'  => 'shield-alt',
				'state' => get_option( 'thessley_unwantedip_enabled', false ) ? 'Enabled' : 'Disabled',
				'level' => get_option( 'thessley_unwantedip_enabled', false )
					? ( get_option( 'thessley_unwantedip_api_key', '' ) ? 'good' : 'warn' )
					: 'warn',
				'note'  => 'blocked IPs only',
			),
			array(
				'key'   => 'malware-scanner',
				'title' => 'Malware Scanner',
				'icon'  => 'warning',
				'state' => $mal_last ? ( $mal_findings ? sprintf( '%d finding(s)', $mal_findings ) : 'Clean' ) : 'Not run',
				'level' => $mal_last ? ( $mal_findings ? 'bad' : 'good' ) : 'warn',
				'note'  => $mal_last ? sprintf( '%d file(s) scanned', (int) ( $mal_last['scanned_count'] ?? 0 ) ) : 'never scanned',
			),
			array(
				'key'   => 'geo-blocker',
				'title' => 'Geo Blocker',
				'icon'  => 'admin-site-alt3',
				'state' => $geo_selected ? sprintf( '%d country(ies)', $geo_selected ) : 'Not configured',
				'level' => $geo_selected ? ( 'block' === $geo_enforce ? 'good' : 'warn' ) : 'warn',
				'note'  => $geo_stats ? sprintf( '%s ranges indexed', number_format_i18n( (int) ( $geo_stats['count'] ?? 0 ) ) ) : 'no dataset yet',
			),
			array(
				'key'   => 'geo-login',
				'title' => 'Geo Login',
				'icon'  => 'lock',
				'state' => $gl_selected ? sprintf( '%d country(ies)', $gl_selected ) : 'Not configured',
				'level' => $gl_selected ? ( 'block' === $gl_enforce ? 'good' : 'warn' ) : 'warn',
				'note'  => 'wp-login.php only',
			),
			array(
				'key'   => 'activity-log',
				'title' => 'Activity Log',
				'icon'  => 'edit-page',
				'state' => $al_count ? sprintf( '%d categor(ies)', $al_count ) : 'Disabled',
				'level' => $al_count ? 'good' : 'warn',
				'note'  => 'posts, plugins, themes, settings',
			),
			array(
				'key'   => 'rate-limiter',
				'title' => 'Rate Limiter',
				'icon'  => 'clock',
				'state' => ! $rl_on ? 'Disabled' : ( 'block' === $rl_mode ? 'Blocking' : 'Log only' ),
				'level' => ! $rl_on ? 'warn' : ( 'block' === $rl_mode ? 'good' : 'warn' ),
				'note'  => sprintf( '%s req/min per IP', number_format_i18n( (int) get_option( 'thessley_ratelimit_per_minute', 300 ) ) ),
			),
			array(
				'key'   => 'geo-map',
				'title' => 'Event Map',
				'icon'  => 'admin-site-alt3',
				'state' => class_exists( 'Thessley_Module_Geo_Map' ) ? sprintf( '%d countries · 7d', count( Thessley_Module_Geo_Map::counts_by_country( 7 ) ) ) : 'Unavailable',
				'level' => 'good', // read-only visualization, nothing to misconfigure
				'note'  => 'blocked + logged events, by country',
			),
		);
	}

	private static function alerts_tg_ready() {
		return get_option( 'thessley_telegram_enabled', false )
			&& get_option( 'thessley_telegram_bot_token', '' )
			&& get_option( 'thessley_telegram_chat_id', '' );
	}

	private static function alerts_email_ready() {
		return get_option( 'thessley_email_enabled', false )
			&& ( get_option( 'thessley_email_address', '' ) || get_option( 'admin_email' ) );
	}

	private static function alerts_ready_count() {
		return ( self::alerts_tg_ready() ? 1 : 0 ) + ( self::alerts_email_ready() ? 1 : 0 );
	}

	private static function alerts_any_enabled() {
		return get_option( 'thessley_telegram_enabled', false ) || get_option( 'thessley_email_enabled', false );
	}

	private static function alerts_channel_summary() {
		$on = array_filter(
			array(
				get_option( 'thessley_telegram_enabled', false ) ? 'Telegram' : null,
				get_option( 'thessley_email_enabled', false ) ? 'Email' : null,
			)
		);
		return $on ? implode( ' + ', $on ) : 'no channel configured';
	}

	private static function integrity_issue_count() {
		$last = get_option( 'thessley_integrity_last_result', array() );
		if ( empty( $last ) ) {
			return 0;
		}
		return count( (array) ( $last['core']['modified'] ?? array() ) )
			+ count( (array) ( $last['core']['missing'] ?? array() ) )
			+ count( (array) ( $last['diff']['added'] ?? array() ) )
			+ count( (array) ( $last['diff']['modified'] ?? array() ) );
	}

	public static function render_dashboard() {
		global $wpdb;

		// phpcs:disable WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching, WordPress.DB.PreparedSQL.InterpolatedNotPrepared, PluginCheck.Security.DirectDB.UnescapedDBParameter
		// $table is always thessley_events_table() (built from $wpdb->prefix, no user input) -- identifiers can't be
		// bound via $wpdb->prepare() placeholders anyway. This is a dashboard summary read over the whole events
		// table (up to a 7-day window or a flat LIMIT 12), not a per-request lookup worth an object-cache group for.
		$table     = thessley_events_table();
		$has_table = $wpdb->get_var( $wpdb->prepare( 'SHOW TABLES LIKE %s', $table ) ) === $table;

		$by_module = array();
		$recent    = array();
		$daily     = array();
		$totals    = array( 'blocked' => 0, 'logged' => 0, 'noted' => 0 );
		$worst     = 0;
		$sev_module = array();

		if ( $has_table ) {
			$worst = (int) $wpdb->get_var(
				"SELECT MAX(severity) FROM {$table} WHERE created_at > DATE_SUB(NOW(), INTERVAL 7 DAY)"
			);

			$sev_rows = $wpdb->get_results(
				"SELECT module, MAX(severity) s FROM {$table}
				 WHERE created_at > DATE_SUB(NOW(), INTERVAL 7 DAY) GROUP BY module",
				ARRAY_A
			) ?: array();
			foreach ( $sev_rows as $r ) {
				$sev_module[ $r['module'] ] = (int) $r['s'];
			}
		}

		if ( $has_table ) {
			$counts = $wpdb->get_results(
				"SELECT module, action, COUNT(*) c
				 FROM {$table}
				 WHERE created_at > DATE_SUB(NOW(), INTERVAL 7 DAY)
				 GROUP BY module, action",
				ARRAY_A
			) ?: array();

			foreach ( $counts as $row ) {
				$by_module[ $row['module'] ][ $row['action'] ] = (int) $row['c'];
				if ( isset( $totals[ $row['action'] ] ) ) {
					$totals[ $row['action'] ] += (int) $row['c'];
				}
			}

			$rows = $wpdb->get_results(
				"SELECT DATE(created_at) d, COUNT(*) c
				 FROM {$table}
				 WHERE created_at > DATE_SUB(NOW(), INTERVAL 7 DAY)
				 GROUP BY DATE(created_at)",
				ARRAY_A
			) ?: array();

			$seen = array();
			foreach ( $rows as $r ) {
				$seen[ $r['d'] ] = (int) $r['c'];
			}
			for ( $i = 6; $i >= 0; $i-- ) {
				$day             = gmdate( 'Y-m-d', strtotime( "-{$i} days" ) );
				$daily[ $day ]   = $seen[ $day ] ?? 0;
			}

			$recent = $wpdb->get_results( "SELECT * FROM {$table} ORDER BY id DESC LIMIT 12" ) ?: array();
		}
		// phpcs:enable WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching, WordPress.DB.PreparedSQL.InterpolatedNotPrepared, PluginCheck.Security.DirectDB.UnescapedDBParameter

		$cards = self::status_cards();

		// Simple posture score: every module contributes equally, partial
		// credit for "on but not enforcing". It's a nudge toward the weak
		// spots, not a claim of measured risk.
		$score = 0;
		foreach ( $cards as $c ) {
			$score += ( 'good' === $c['level'] ) ? 1 : ( ( 'warn' === $c['level'] ) ? 0.5 : 0 );
		}
		$score   = (int) round( ( $score / max( 1, count( $cards ) ) ) * 100 );
		$s_level = $score >= 85 ? 'good' : ( $score >= 60 ? 'warn' : 'bad' );
		$s_label = $score >= 85 ? 'Strong' : ( $score >= 60 ? 'Needs attention' : 'Weak' );

		// Core protection: the baseline modules a site should turn on
		// regardless of what it is — as opposed to optional integrations
		// (Telegram, IP Sharing, Geo Blocker/Login, Activity Log) that many
		// sites will legitimately never want, and User Watchdog/Event Map
		// whose "not good" states are live alerts or read-only views, not
		// unfinished setup. Keeping this list separate from the general
		// attention line means the headline banner only ever nags about
		// things actually worth finishing, not things worth ignoring.
		$core_keys = array(
			'ip-blocklist',
			'query-guard',
			'login-guard',
			'headers',
			'user-enum',
			'file-integrity',
			'malware-scanner',
			'vuln-scanner',
			'rate-limiter',
			'hardening',
		);

		$core_gaps = array_values(
			array_filter(
				$cards,
				function ( $c ) use ( $core_keys ) {
					return in_array( $c['key'], $core_keys, true ) && 'good' !== $c['level'];
				}
			)
		);

		$attention = array_values(
			array_filter(
				$cards,
				function ( $c ) use ( $core_keys ) {
					return 'good' !== $c['level'] && ! in_array( $c['key'], $core_keys, true );
				}
			)
		);

		// CSS is enqueued externally via enqueue_assets() (admin_enqueue_scripts),
		// not printed here — by the time this callback runs, wp-admin's <head>
		// has already been sent.
		?>
		<div class="wrap thessley thessley-dash">
			<h1 class="thessley-title">
				<img src="<?php echo esc_attr( self::logo_data_uri() ); ?>" alt="" width="30" height="30">
				Thessley Security Hardening
			</h1>

			<div class="thessley-hero">
				<div class="thessley-score thessley-score--<?php echo esc_attr( $s_level ); ?>">
					<div class="thessley-score__ring" style="--pct:<?php echo esc_attr( $score ); ?>">
						<div class="thessley-score__num"><?php echo esc_html( $score ); ?><span>%</span></div>
					</div>
					<div class="thessley-score__label"><?php echo esc_html( $s_label ); ?></div>
				</div>

				<div class="thessley-hero__stats">
					<div class="thessley-stat thessley-stat--bad">
						<span class="dashicons dashicons-dismiss"></span>
						<div>
							<strong><?php echo esc_html( number_format_i18n( $totals['blocked'] ) ); ?></strong>
							<span>blocked · 7 days</span>
						</div>
					</div>
					<div class="thessley-stat thessley-stat--warn">
						<span class="dashicons dashicons-visibility"></span>
						<div>
							<strong><?php echo esc_html( number_format_i18n( $totals['logged'] ) ); ?></strong>
							<span>would block (log only)</span>
						</div>
					</div>
					<?php list( $w_label, $w_color ) = thessley_severity_meta( $worst ); ?>
					<div class="thessley-stat">
						<span class="dashicons dashicons-warning" style="color:<?php echo esc_attr( $worst ? $w_color : '#646970' ); ?>"></span>
						<div>
							<strong><?php echo $worst ? esc_html( $worst ) . '<span style="font-size:13px;font-weight:400;color:#646970">/20</span>' : '—'; ?></strong>
							<span>worst severity<?php echo $worst ? esc_html( ' · ' . $w_label ) : ''; ?></span>
						</div>
					</div>

					<?php if ( $daily ) : ?>
						<div class="thessley-spark">
							<?php
							$max = max( 1, max( $daily ) );
							foreach ( $daily as $day => $n ) :
								$h = max( 3, (int) round( ( $n / $max ) * 46 ) );
								?>
								<span class="thessley-spark__bar"
									style="height:<?php echo esc_attr( $h ); ?>px"
									title="<?php echo esc_attr( sprintf( '%s — %d event(s)', date_i18n( 'D j M', strtotime( $day ) ), $n ) ); ?>"></span>
							<?php endforeach; ?>
						</div>
					<?php endif; ?>
				</div>
			</div>

			<?php if ( $core_gaps ) : ?>
				<div class="thessley-protect thessley-protect--bad">
					<div class="thessley-protect__head">
						<span class="dashicons dashicons-shield-alt"></span>
						<div>
							<strong>You're not fully protected yet</strong>
							<span><?php echo esc_html( sprintf( '%d of %d core module(s) still need attention.', count( $core_gaps ), count( $core_keys ) ) ); ?></span>
						</div>
					</div>
					<ul class="thessley-protect__list">
						<?php foreach ( $core_gaps as $g ) : ?>
							<li>
								<a href="<?php echo esc_url( Thessley_Menu_Router::url( $g['key'] ) ); ?>">
									<span class="dashicons dashicons-arrow-right-alt2"></span>
									<strong><?php echo esc_html( $g['title'] ); ?></strong>
									<em><?php echo esc_html( $g['state'] ); ?></em>
								</a>
							</li>
						<?php endforeach; ?>
					</ul>
				</div>
			<?php else : ?>
				<div class="thessley-protect thessley-protect--good">
					<div class="thessley-protect__head">
						<span class="dashicons dashicons-yes-alt"></span>
						<div>
							<strong>Core protection fully configured</strong>
							<span>Every baseline module is on and enforcing.</span>
						</div>
					</div>
				</div>
			<?php endif; ?>

			<?php if ( $attention ) : ?>
				<div class="thessley-attention">
					<span class="dashicons dashicons-info"></span>
					<div>
						<strong>Optional, not yet set up:</strong>
						<?php
						$links = array();
						foreach ( $attention as $a ) {
							$links[] = sprintf(
								'<a href="%s">%s <em>(%s)</em></a>',
								esc_url( Thessley_Menu_Router::url( $a['key'] ) ),
								esc_html( $a['title'] ),
								esc_html( strtolower( $a['state'] ) )
							);
						}
						echo wp_kses_post( implode( ' · ', $links ) );
						?>
					</div>
				</div>
			<?php endif; ?>

			<h2 class="thessley-h2">Modules</h2>
			<div class="thessley-grid">
				<?php foreach ( $cards as $card ) : ?>
					<?php
					$blocked = $by_module[ $card['key'] ]['blocked'] ?? 0;
					$logged  = $by_module[ $card['key'] ]['logged'] ?? 0;
					$noted   = $by_module[ $card['key'] ]['noted'] ?? 0;
					$total   = $blocked + $logged + $noted;
					?>
					<a class="thessley-card thessley-card--<?php echo esc_attr( $card['level'] ); ?>"
						href="<?php echo esc_url( Thessley_Menu_Router::url( $card['key'] ) ); ?>">
						<div class="thessley-card__top">
							<span class="thessley-card__icon dashicons dashicons-<?php echo esc_attr( $card['icon'] ); ?>"></span>
							<span class="thessley-card__title"><?php echo esc_html( $card['title'] ); ?></span>
							<?php if ( ! empty( $sev_module[ $card['key'] ] ) ) : ?>
								<?php list( $cs_label, $cs_color ) = thessley_severity_meta( $sev_module[ $card['key'] ] ); ?>
								<span class="thessley-sevdot"
									style="background:<?php echo esc_attr( $cs_color ); ?>"
									title="<?php echo esc_attr( sprintf( 'Worst severity in 7 days: %d (%s)', $sev_module[ $card['key'] ], $cs_label ) ); ?>"><?php echo esc_html( $sev_module[ $card['key'] ] ); ?></span>
							<?php endif; ?>
						</div>
						<div class="thessley-pill"><?php echo esc_html( $card['state'] ); ?></div>
						<div class="thessley-card__note"><?php echo esc_html( $card['note'] ); ?></div>
						<div class="thessley-card__foot">
							<?php if ( $total ) : ?>
								<?php if ( $blocked ) : ?>
									<span class="thessley-chip thessley-chip--bad"><?php echo esc_html( number_format_i18n( $blocked ) ); ?> blocked</span>
								<?php endif; ?>
								<?php if ( $logged ) : ?>
									<span class="thessley-chip thessley-chip--warn"><?php echo esc_html( number_format_i18n( $logged ) ); ?> logged</span>
								<?php endif; ?>
								<?php if ( $noted && ! $blocked && ! $logged ) : ?>
									<span class="thessley-chip"><?php echo esc_html( number_format_i18n( $noted ) ); ?> events</span>
								<?php endif; ?>
							<?php else : ?>
								<span class="thessley-chip thessley-chip--quiet">no activity</span>
							<?php endif; ?>
						</div>
					</a>
				<?php endforeach; ?>
			</div>

			<h2 class="thessley-h2">
				Recent activity
				<a class="thessley-h2__link" href="<?php echo esc_url( Thessley_Menu_Router::url( 'event-log' ) ); ?>">View full log →</a>
			</h2>

			<?php if ( empty( $recent ) ) : ?>
				<div class="thessley-empty">
					<span class="dashicons dashicons-yes-alt"></span>
					<p>No events recorded yet. Modules in log-only mode will record here as traffic arrives.</p>
				</div>
			<?php else : ?>
				<div class="thessley-table-scroll">
				<table class="thessley-table">
					<thead>
						<tr>
							<th style="width:56px">Sev</th>
							<th style="width:130px">Time</th>
							<th style="width:120px">Module</th>
							<th style="width:170px">Event</th>
							<th style="width:90px">Action</th>
							<th style="width:120px">IP</th>
							<th>Detail</th>
						</tr>
					</thead>
					<tbody>
					<?php foreach ( $recent as $row ) : ?>
						<?php list( $rs_label, $rs_color ) = thessley_severity_meta( $row->severity ); ?>
						<tr>
							<td>
								<span class="thessley-sevdot" style="background:<?php echo esc_attr( $rs_color ); ?>"
									title="<?php echo esc_attr( $rs_label ); ?>"><?php echo esc_html( (int) $row->severity ); ?></span>
							</td>
							<td class="thessley-nowrap"><?php echo esc_html( mysql2date( 'M j, H:i', $row->created_at ) ); ?></td>
							<td><span class="thessley-mod"><?php echo esc_html( $row->module ); ?></span></td>
							<td><code><?php echo esc_html( $row->event ); ?></code></td>
							<td>
								<?php if ( 'blocked' === $row->action ) : ?>
									<span class="thessley-chip thessley-chip--bad">blocked</span>
								<?php elseif ( 'logged' === $row->action ) : ?>
									<span class="thessley-chip thessley-chip--warn">logged</span>
								<?php else : ?>
									<span class="thessley-chip thessley-chip--quiet">noted</span>
								<?php endif; ?>
							</td>
							<td class="thessley-nowrap"><code><?php echo esc_html( $row->ip ); ?></code></td>
							<td class="thessley-detail"><?php echo esc_html( $row->detail ); ?></td>
						</tr>
					<?php endforeach; ?>
					</tbody>
				</table>
				</div>
			<?php endif; ?>
		</div>
		<?php
	}


	private static function load_module( $module ) {
		$file = THESSLEY_PLUGIN_DIR . "includes/modules/{$module}/module.php";
		if ( file_exists( $file ) ) {
			require_once $file;
		}
	}

	/**
	 * Which of the per-module early-gate check files should run. The
	 * mu-plugin loader requires each listed module's check.php straight
	 * from this plugin's own folder, so nothing but the loader itself is
	 * ever copied into wp-content. Only the module slug is stored (the
	 * loader re-validates it and only ever builds a path from a fixed
	 * directory plus that slug), never a path.
	 */
	public static function register_check( $slug ) {
		$active = get_option( 'thessley_active_checks', array() );
		$active = is_array( $active ) ? $active : array();
		if ( ! in_array( $slug, $active, true ) ) {
			$active[] = $slug;
			update_option( 'thessley_active_checks', array_values( $active ) );
		}
	}

	public static function unregister_check( $slug ) {
		$active = get_option( 'thessley_active_checks', array() );
		$active = is_array( $active ) ? $active : array();
		if ( in_array( $slug, $active, true ) ) {
			update_option( 'thessley_active_checks', array_values( array_diff( $active, array( $slug ) ) ) );
		}
	}

	/**
	 * The early-gate loader finds this plugin's check files under
	 * WP_PLUGIN_DIR by folder name; the folder is normally the slug, but
	 * it is recorded rather than assumed.
	 */
	private static function sync_plugin_folder() {
		$folder = basename( untrailingslashit( THESSLEY_PLUGIN_DIR ) );
		if ( get_option( 'thessley_plugin_folder' ) !== $folder ) {
			update_option( 'thessley_plugin_folder', $folder );
		}
	}

	/**
	 * Compiled datasets (IP ranges, geo index, trusted networks) live in
	 * wp-content/uploads/thessley-security-hardening/, resolved with
	 * wp_upload_dir() and shielded from direct web access. The early gate
	 * runs before plugins load, where filters on the uploads location may
	 * not be registered yet, so the resolved path is stored in an option
	 * for it to read back rather than recomputed.
	 *
	 * Only ever called by code that writes data; readers use
	 * thessley_data_file() from the mu-loader. Returns '' when the uploads
	 * directory cannot be used, in which case callers skip the write.
	 */
	public static function data_dir() {
		$uploads = wp_upload_dir( null, false );
		if ( ! empty( $uploads['error'] ) || empty( $uploads['basedir'] ) ) {
			return '';
		}

		$dir = untrailingslashit( $uploads['basedir'] ) . '/thessley-security-hardening';
		if ( ! is_dir( $dir ) && ! wp_mkdir_p( $dir ) ) {
			return '';
		}

		if ( ! file_exists( $dir . '/index.php' ) ) {
			self::fs_put_contents( $dir . '/index.php', "<?php\n// Silence is golden.\n" );
		}
		if ( ! file_exists( $dir . '/.htaccess' ) ) {
			self::fs_put_contents(
				$dir . '/.htaccess',
				"Options -Indexes\n<IfModule mod_authz_core.c>\nRequire all denied\n</IfModule>\n<IfModule !mod_authz_core.c>\nOrder allow,deny\nDeny from all\n</IfModule>\n"
			);
		}

		if ( get_option( 'thessley_data_dir' ) !== $dir ) {
			update_option( 'thessley_data_dir', $dir );
		}

		return $dir;
	}

	/** @return string full path for a compiled data file, or '' if the data directory is unavailable */
	public static function data_file( $name ) {
		$dir = self::data_dir();
		return '' === $dir ? '' : $dir . '/' . $name;
	}

	/**
	 * Packs sorted [start, end] IPv4 integer pairs into a flat binary
	 * string, 8 bytes per range (two big-endian uint32s). The early gate
	 * binary-searches it in place; it is data, not code, so nothing in
	 * the uploads folder is ever executed.
	 *
	 * @param array<int, array{0:int,1:int}> $ranges
	 */
	public static function pack_ranges( array $ranges ) {
		$out = '';
		foreach ( $ranges as $r ) {
			$out .= pack( 'NN', $r[0], $r[1] );
		}
		return $out;
	}

	/**
	 * Atomic-ish write of a compiled data file: temp file then rename, so
	 * the early gate never reads a half-written one.
	 */
	public static function write_data_file( $name, $contents ) {
		$file = self::data_file( $name );
		if ( '' === $file ) {
			return false;
		}
		$tmp = $file . '.tmp-' . wp_generate_password( 8, false );
		if ( ! self::fs_put_contents( $tmp, $contents ) ) {
			return false;
		}
		return self::fs_move( $tmp, $file, true );
	}

	/**
	 * One-time move of everything earlier versions kept under
	 * wp-content/mu-plugins/wp-thessley-checks/ (the copied check files
	 * plus data/, which used PHP array files) into the uploads data
	 * directory in its current non-PHP formats, then removes the old
	 * folder. Nothing is re-downloaded: the geo index and trusted-networks
	 * list are moved, the PHP array files are converted.
	 */
	private static function migrate_data_to_uploads() {
		if ( get_option( 'thessley_data_moved' ) ) {
			return;
		}

		$old = THESSLEY_CHECKS_DIR . '/data';
		if ( is_dir( $old ) ) {
			$dir = self::data_dir();
			if ( '' === $dir ) {
				return; // uploads not usable right now; try again next request
			}

			if ( file_exists( $old . '/geo-country-index.bin' ) && ! file_exists( $dir . '/geo-country-index.bin' ) ) {
				self::fs_move( $old . '/geo-country-index.bin', $dir . '/geo-country-index.bin', true );
			}
			if ( file_exists( $old . '/trusted-networks-remote.conf' ) && ! file_exists( $dir . '/trusted-networks-remote.conf' ) ) {
				self::fs_move( $old . '/trusted-networks-remote.conf', $dir . '/trusted-networks-remote.conf', true );
			}

			// These are this plugin's own previously generated files (arrays
			// of integers/labels), read once here purely to convert them.
			if ( file_exists( $old . '/ip-blocklist-ranges.php' ) ) {
				$ranges = include $old . '/ip-blocklist-ranges.php';
				if ( is_array( $ranges ) ) {
					self::write_data_file( 'ip-blocklist-ranges.bin', self::pack_ranges( $ranges ) );
				}
			}
			if ( file_exists( $old . '/ip-blocklist-by-source.php' ) ) {
				$by_source = include $old . '/ip-blocklist-by-source.php';
				if ( is_array( $by_source ) ) {
					$encoded = array();
					foreach ( $by_source as $label => $ranges ) {
						$encoded[ $label ] = base64_encode( self::pack_ranges( $ranges ) );
					}
					self::write_data_file( 'ip-blocklist-by-source.json', wp_json_encode( $encoded ) );
				}
			}
			if ( file_exists( $old . '/trusted-networks-by-source.php' ) ) {
				$by_heading = include $old . '/trusted-networks-by-source.php';
				if ( is_array( $by_heading ) ) {
					self::write_data_file( 'trusted-networks-by-source.json', wp_json_encode( $by_heading ) );
				}
			}
			if ( file_exists( $old . '/geo-country-names.php' ) ) {
				$names = include $old . '/geo-country-names.php';
				if ( is_array( $names ) ) {
					self::write_data_file( 'geo-country-names.json', wp_json_encode( $names ) );
				}
			}
		}

		if ( is_dir( THESSLEY_CHECKS_DIR ) ) {
			self::fs_delete( THESSLEY_CHECKS_DIR, true );
		}

		update_option( 'thessley_data_moved', 1 );
	}

	/**
	 * Defines the shared early-gate helper functions in this process. Prefers
	 * the deployed mu-plugin copy; falls back to the identical file shipped
	 * inside this plugin when that copy doesn't exist (deployment failed, or
	 * hasn't happened yet this request), so a filesystem the plugin can't
	 * write to degrades to "early-gate blocking is off" rather than a fatal
	 * "failed opening required". Every function in that file is
	 * function_exists()-guarded, so loading the bundled copy is safe even if
	 * the deployed one appears later.
	 */
	private static function load_helpers() {
		$file = file_exists( THESSLEY_MU_DEST ) ? THESSLEY_MU_DEST : THESSLEY_MU_SOURCE;
		if ( file_exists( $file ) ) {
			require_once $file;
		}
	}

	/** Tells an admin when the early-gate mu-plugin couldn't be deployed, instead of failing silently. */
	public static function maybe_notice_mu_loader_missing() {
		if ( file_exists( THESSLEY_MU_DEST ) || ! current_user_can( 'manage_options' ) ) {
			return;
		}
		printf(
			'<div class="notice notice-warning"><p>%s</p></div>',
			esc_html__( 'Thessley Security Hardening could not install its early-request gate into wp-content/mu-plugins (WordPress could not write there). The plugin\'s admin screens still work, but blocking before WordPress loads is inactive until that directory is writable.', 'thessley-security-hardening' )
		);
	}

	private static function copy_mu_loader() {
		if ( ! file_exists( WPMU_PLUGIN_DIR ) ) {
			wp_mkdir_p( WPMU_PLUGIN_DIR );
		}
		self::fs_copy( THESSLEY_MU_SOURCE, THESSLEY_MU_DEST, true );

		// Every other rewritten data file in this plugin does this; the
		// mu-loader itself — by far the most consequential one, since it
		// defines every shared function — never did. Without it, a request
		// handled by a worker process that already had the old bytecode
		// opcache-compiled can keep serving stale function definitions
		// until that cache entry's own revalidation timer fires, which is
		// a real window for a fatal "undefined function" on a real request
		// if this file changed (new function added) during it — confirmed
		// live, not hypothetical: hit a real admin session's own
		// admin-ajax request during this exact deploy window.
		if ( function_exists( 'opcache_invalidate' ) ) {
			opcache_invalidate( THESSLEY_MU_DEST, true );
		}
	}

	private static function remove_mu_loader() {
		if ( file_exists( THESSLEY_MU_DEST ) ) {
			self::fs_delete( THESSLEY_MU_DEST );
		}
	}

	/**
	 * Keep the deployed mu-plugin file in sync with the version shipped in
	 * this plugin (e.g. after a plugin update), without requiring reactivation.
	 */
	private static function ensure_mu_loader_current() {
		if ( ! file_exists( THESSLEY_MU_DEST )
			|| md5_file( THESSLEY_MU_DEST ) !== md5_file( THESSLEY_MU_SOURCE ) ) {
			self::copy_mu_loader();
		}
	}
}
