"""Script used to test the /api/v1/system/certificate endpoint."""
import e2e_test_framework
import json
import base64
import pytz
from datetime import datetime, timedelta
from cryptography import x509
from cryptography.hazmat._oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa

# Constants
CRT = "LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCk1JSUR5VENDQXJHZ0F3SUJBZ0lVZUZacVZwcXlDNXRqa0I2TWNwdnIybGlHRDc0d0RRWU" \
      "pLb1pJaHZjTkFRRUwKQlFBd2N6RUxNQWtHQTFVRUJoTUNWVk14RFRBTEJnTlZCQWdNQkZWMFlXZ3hEakFNQmdOVkJBY01CVkJ5YjNadgpN" \
      "UnN3R1FZRFZRUUtEQkpxWVhKbFpHaGxibVJ5YVdOcmMyOXVNVE14RWpBUUJnTlZCQXNNQ1VSbGRtVnNiM0JsCmNqRVVNQklHQTFVRUF3d0" \
      "xjR1p6Wlc1elpTMWhjR2t3SUJjTk1qQXdPVEk0TVRnek1EQXlXaGdQTXpBeU1EQXgKTXpBeE9ETXdNREphTUhNeEN6QUpCZ05WQkFZVEFs" \
      "VlRNUTB3Q3dZRFZRUUlEQVJWZEdGb01RNHdEQVlEVlFRSApEQVZRY205MmJ6RWJNQmtHQTFVRUNnd1NhbUZ5WldSb1pXNWtjbWxqYTNOdm" \
      "JqRXpNUkl3RUFZRFZRUUxEQWxFClpYWmxiRzl3WlhJeEZEQVNCZ05WQkFNTUMzQm1jMlZ1YzJVdFlYQnBNSUlCSWpBTkJna3Foa2lHOXcw" \
      "QkFRRUYKQUFPQ0FROEFNSUlCQ2dLQ0FRRUFvQ2x3d1Jzajg4Tnk0Z1Zid2NhRUYzU0s4SlQvZEowQUxjV1F4Wnh1WUt3MgpHMldCK0Y3RW" \
      "ZBbTNVN21qNEt0bWF0ZEhEWVppZ1c0T0dzSWE0dVZKaGhVWDJ0RlMvcGQ2UHlFa2ZyMHFvcm1nCm84MnNJUW9WZS84YTRVRzJYeXl1SkRO" \
      "Vks2SjJJS1hodUt2dEpCVk5xZlJoZExVNDNHLzAxZjBnTkwrSlE4VDMKVlpCUFgyZXpMK1hNUGg2ZkFpRG5MNmp2c0F3ZTZ4cEhEYTVDL0" \
      "l1VmJ6Z2V6YUNiREFneVcvZFowcDltNzNPNApBWnV3UXVwUUNTUkZWenJnS3dyaUF0SDhnVGRtVWtKdG10a2hwL0R3bTRha2k3dmpsYTI0" \
      "R0JsZXVlQzJ6azhZCkhMMGxERENBeWtsM2o5UEpUM0ttbC9LVzFkQ3FvcTZTWmYxNTRZZzlEd0lEQVFBQm8xTXdVVEFkQmdOVkhRNEUKRm" \
      "dRVU5veC9UdE45SWxLMlA3YjF1ZzJ1dHJ2ZGtXY3dId1lEVlIwakJCZ3dGb0FVTm94L1R0TjlJbEsyUDdiMQp1ZzJ1dHJ2ZGtXY3dEd1lE" \
      "VlIwVEFRSC9CQVV3QXdFQi96QU5CZ2txaGtpRzl3MEJBUXNGQUFPQ0FRRUFhT2xsCmMrbDRHTXZjNDBKUnlGRDdoeUJlSkVsN0x5NmVpeF" \
      "pxNUdzU0hpbEJiT2M5MmQ3b1dja3ptZGNIT0hqdlRwU3kKTXpOclVqcGFoMlZDSXZXMXhXaHEwMWJMQnJwRmtqNmNwbkY3d2NTVnlSODdS" \
      "OG4za0x2dlRqMEhoVE9rb1FRVwp2VGVTei9RaytFVm9SeHdob3J5U2VnWW9yQTRScUZyd2c1a3puZGVrM0gwSXcyQzkxZVBUbjRmSU5mTk" \
      "pUTnhHCmc3eDhxWCtySFl4L0R2Y0hjSVEzYVlzYVJ1TXNTYmtHYjdwUXZmOXNneE1weC9ucU8xS0RKVUUrOTVRQTJOa3oKTldYeDFaeVVV" \
      "cUNOd0RVVENaczNzczVYSWJrdTJSWXhmNWxMTG03YnQrUHZwY3RVOVRSUzlmQWUvQXpldjI3KwpTQzM2Nm1uYnh0OG5xVnR1K0E9PQotLS" \
      "0tLUVORCBDRVJUSUZJQ0FURS0tLS0tCg=="
PRV = "LS0tLS1CRUdJTiBQUklWQVRFIEtFWS0tLS0tCk1JSUV2UUlCQURBTkJna3Foa2lHOXcwQkFRRUZBQVNDQktjd2dnU2pBZ0VBQW9JQkFRQ2" \
      "dLWERCR3lQenczTGkKQlZ2QnhvUVhkSXJ3bFA5MG5RQXR4WkRGbkc1Z3JEWWJaWUg0WHNSOENiZFR1YVBncTJacTEwY05obUtCYmc0YQp3" \
      "aHJpNVVtR0ZSZmEwVkwrbDNvL0lTUit2U3FpdWFDanphd2hDaFY3L3hyaFFiWmZMSzRrTTFVcm9uWWdwZUc0CnErMGtGVTJwOUdGMHRUam" \
      "NiL1RWL1NBMHY0bER4UGRWa0U5Zlo3TXY1Y3crSHA4Q0lPY3ZxTyt3REI3ckdrY04KcmtMOGk1VnZPQjdOb0pzTUNESmI5MW5TbjJidmM3" \
      "Z0JtN0JDNmxBSkpFVlhPdUFyQ3VJQzBmeUJOMlpTUW0yYQoyU0duOFBDYmhxU0x1K09WcmJnWUdWNjU0TGJPVHhnY3ZTVU1NSURLU1hlUD" \
      "A4bFBjcWFYOHBiVjBLcWlycEpsCi9YbmhpRDBQQWdNQkFBRUNnZ0VBRlpCKzFnRkpmZkM2N3lPNWp3V2prMlRsc0M3ZmxsdnRRanh2bWF2" \
      "T1VNWGYKSXlFdnRybEx5MGVqbjJwSFhtQzFrWDBhMi85VUZBazFiUFRsbWRjMVp4QS8vZjVoSmxaTzUyRVhBTm1IZkJGeQpSNXZScVVFcV" \
      "UxK3R4dGFLTDVaY2ZCTk5UR3E3YlBub3dteWpxVkFVL09VaW1nd3NjOEcvUFhDdmZXcXNtS3NkCit5WEd0dlJJNC9sdmtrbDJMRzRGc000" \
      "bE9hMXZJNXovZ2Zhb0FEdUZsVUpsVHk4S2FCVElMZW9tTmJRc01jSEsKeDVkTEFXR0lieXB4K1pQQnQ3VTZ0SnFlOElScHZlbmR2cDZoTT" \
      "hFS2x4dlNxMVNVbFNya3ltT0dtL0NKSzRSbgprVmV1L1pnUjlTbW1tTm9MM2RTUk0vMzJIUTkxTkpJdlJWVGRMU1RhZ1FLQmdRREt3VXI1" \
      "dlJJYURjSGlGZjRzCnhicW1Gbm4vYkVBWWNUclFXaFllZGRQY3dkczJNWjNwcXh6Z3doSGlUYVFnMEwrUFJsV000TytlbXAwOFVDM3QKcW" \
      "F4dys4ZDNYVjgzSGZadHJFRTJqQkd5V0l5dHFzWlBuS2haa3VhdkN1NWkzUlNLVG1CcUw3cGF6TDZGRXhEeAo4OTU2aWdPR3hXbkhvRE1y" \
      "KzRla1ZQZzExd0tCZ1FES09MZDRpd20xTlpHWHA3K21TVVpsVnM4a0J1aysyRGNhCjBvUWdKaEJ4M2FPZmRESTU0Q0Zqb0ZQUytBZjc2T3" \
      "FSMUlNYWl5a1BMWFVoZzBsdHBac3VJWlBSTFFmdUpuK20KajhXbGFWT1NDeFoxMjkvKzZ1RGZwTUR1WFVZeW9wNS9QK0RJSzJhY2NGTWlz" \
      "THRHLzZncEJWN2ZBU2QxazQ4RQpRUWNOYlBCYmlRS0JnUUNDZXBmRVZhOVRndXoxa00rc2dtYVdRYnFxN0Qvbk90N3RmRHZseUUvYUxncm" \
      "pPbFQwCkxnRDhod2U1U2R2SW5tM1lSeHdBK0RSY0xnWG43WFZSRDdNQVZwZExzcFAyeFZwenc3bUgzK1gzanRLaFpGZ1EKbmJFZFM5TVdi" \
      "SU55cmZGcysvbEIvSXNCcWVjbGZscVdTaWt2VktmbVVCNjlyOU9laDFVSUpRSkNxd0tCZ0FveQpyQVgzTlFrZlozVTNiM0hLVmpOOEdqd2" \
      "Q0UnRiT2dRdlE1eC9idXJmRzRaS0ROSmdYQzZ6QWljc2ZQS1dQMllWClNudEhNMDNoby91SnJHVk1LYlE4MjBCOFBkOGpyK0pOYzlFd3E1" \
      "YzgyZWdkcTRFbWhTcWlHMXlwOVlWT01DSUkKcmFSS2xBVWxvUHVwMy9mbm9xcFc2LzdoQndWbDZKdDFVQTY4Uks3SkFvR0FXL0ZkSVk0Y3" \
      "djMEZHMjN6dWYvUApTZTNESktTZ3BYSlA2ZDZ2SjRDNnAvRDcwNytUQ1JpWVBQMnJ4QlpDRk1ZczJ2M01BN2lvM0lpV3VjOStabHFMCkxW" \
      "bk4zNEQ1dGZhMExnQzArVFZtOTNEZHE2SFd1WWdYMUx0MzFXeFhMMkpXREpmazcxc3prNW51NGRkSTNkdnAKU0ducTB1UjRlR0IxK2ZRNH" \
      "luNlgydkk9Ci0tLS0tRU5EIFBSSVZBVEUgS0VZLS0tLS0K"



class APIE2ETestSystemCertificate(e2e_test_framework.APIE2ETest):
    """Class used to test the /api/v1/system/certificate endpoint."""
    uri = "/api/v1/system/certificate"
    csr_refid = ""
    csr_cert = ""

    ca_key_b64 = "LS0tLS1CRUdJTiBSU0EgUFJJVkFURSBLRVktLS0tLQ0KTUlJSktRSUJBQUtDQWdFQXc5RUFnNXpqaTljMnJGRUpQK2VXZG41bkJmT29GNDJlK1g3amJoZFl0Zmk0VHEzZQ0KUXVxcEpBUUk4VkdHcU0zY083b0pYOUFUUlZmbGwwbGRCN1IxbUZHL3FxL09PdksrV2s2OURXR0xQOUtoczN4Wg0KalF3bFFVMmtqSSszRWhSZXY5S0lNOEFFMDFMNmFlUXROZWdhRVRMckd3NHNiWmRkTFB1NmFKYWtQM0Rod2Nsdw0KSjdublR4M1cwQjE3S0NRbEgrSGtOSXp3a2djMWVoWlhHUFF1L05tU2FSNFZJRHZ6dytBdm43STdSVnZ6d09XdA0KWTdJMkUzS1VHNVRRbEE4KzhRb3BiTEwwUm1QS0ZTTkF2TVhwK2VsRzlQZzdsdmFnMUdPOCtoSXBHdmFqRjlWaw0KWFZIZWVtZ0h1RDQ2YWlIOVBOSS8wc2Yxc2tLUDcya0V4V09vRTIvZGRZTHZuditFaVR5WU1OVHkzTVdyT2YweA0KMFBlUkpvM1JTYXpRZlBMSWdRc1VORzNscmNFbUVDSGcwd1ZDRlFEVFR1bVNsb2FXWERVc044MzFjbVo3TTZzUQ0KQTBCVjFVYXI3V055eXVEcHlualpITWU3L3NmRTBGY3I1M1Q3cVV6R29hamMrbDJMV1V5b2FvRk83UU8wVkc0bg0Kc2FsVXlVeWVuR2ZFd1R4QUJHQW1FR3IrWVRXTEpjZ1kwNWtLUnhZR3ZER3hGZDdxUGVtNEw3T2g5ZS9GY2lPZg0KcDgxMEpITDA1Rm5IVFRJWExzVEZaWURxWTN6enVTQ05ZTTJjUUVVSUluOVo2QUZGYWk2VUk0NHFiMFNOdkN1eQ0KV3pVcHpGZTVUODlaL0N6eHVVTUpidThKbFJqRVk1QWVQa1F1cXJIMnZ1SjJTcUhvck9DdXRKSHNRUE1DQXdFQQ0KQVFLQ0FnQSsyeDhNSUZkV2N5M2tvRnFVdmRVcGtpZWwzSEhQcGJFcksxVDc2TmljQ1F1NGpjMHpzN201aXVZSA0KK0lCK1BSNTl1Wmo2dllNQ0ZsWG5lekEyb2ZIQmhEUS9LUkhORUZDVUVvUlRBRVcvcGZBcitqV1F0aDViV1A0Qg0KOUx2eVBNR3hWM1pMRGs4K09udVJkQ0lqRks4UmFFUFp1bkgrZDhEOENJM3N0clpnZXU2czB1bUNod1U5K3prUw0KTXZSdWpUT3hpVVJFcmgwbTh0TnlyaXNsSW5UV3kweFpHOFB5UmV4WXF1VCtvU3F2ZC9YRnJMUTh0Vjd3WFM0Mw0Kc0V4SHlxRU1wSk5waGdRdGVDak5JalRNbzhjWVpvNVZZajFXbHpKSEd3RDFVTkVMQzdLTW12NE5pcE1jdmJvRQ0KcFUwQTlvb2dkT2p4MHlnR0lhR3NXd3lpQS94V09IeENoS2RPMit4dGRiY093b000U0c5MnMzb0lFSE1KUHNoaA0KcmxxdUptSzdZOGFBcXlJNDhRYkk3VDA2OHIxeExxakV4WGNLMVdUeDNRWVhmTGhGQ01hZFgzMEhQSFdYZ29qNg0KSEUzakVkREhlcERza0oyc1FKcmFxZi9wbGdYOEphY2ZBVzVQdy9CbFdFMFU3d1lhRnp4a3VjcmIra01kd3BueQ0KeVJZSEJ2K3FOdzFCbzBoVDhLWW85ekViUTZLOVJRaE5rQzF1cWE4dzdkeTV0NnQ4U2ZyR1BlYmozSGpzWUl4dg0KN3NhUEN6ejhDUi9VdStVdnI2M2I2Zks5V28wNUYzWkNqMXk5RGc1VVpZK2ppcWx0ZndTRkg1UEczSE5VcHNMTA0KVysvaWdCb2dPbTg0NmIyUzdKd3RzanpPR2VMbmhicWJVR0hXK3pCTStwS3dpMG1Md1FLQ0FRRUE5dDBqM0pDcw0KTnh2TUQyZVYxMksrYlpFSVpUNTFIT3VOcjZ1SU05UUV1QkluS2wzUVFsdzZCV084Y0hEbUVBazJiZ0hPdXAzbw0KTjJBNnE4dTJSYnJDdWlEMm9qdU9yNmtvYUNySHhFVlpnM2xFWFR6T2t5TjFuMmRKbDBaaWhJWVN4QjJpaTFTcQ0KazAyV1pIVHVEYm5TSmh2WHpxQjI5clBNeis5TWVaM05NNi9GQ0xLdkp5WkhCR01MMGJUUkduOEkxQ0hjaWkzWg0Ka1B2NmtmcHR4eFc2MlZNZm5IMHF6Q1p4QURPUDhJUXcxbTlPUmFBV21TSS9FRFZsVUxaVm1uK3ZHTWp6YndjRw0KenZuOFV1WllKaHhjUzNuL0FvM2NKTU55NlYwckdnaElXbTNnaCtPTHNIdlcyd2tXeTBHcmk1OEtFaUxQeUp3cw0KQmdPaitvalZXNm9MMHdLQ0FRRUF5eEE1VFBxeGtQQnVaSGV0MGpxeHc1Z3d0TGl5alhnNDl6NmNoOWNYcDdNYQ0Kekt2Zk1QYzBKYTZFTEp3N0ZWNDBlVGNlZk5ESFV0cEp4SkZWaC8walkxZXhlbzZNTGVhS0ZxaWRqbTdWclkveg0KOFAxZE55a2VJS3hYaVJlbUNqTzZKUlBobjRHT003STNMNVJaU3pxL214dzl6ZWpUNTRubXZwSlBCNFBEM2pzcg0KelRSb3NaamJiS1pjSHdqTUdoT0puR0JDcXY0M3dIU05sZHN2OXJzVkJHeG4wTUY2eVRIWkRwZ1lYZGQwR1dnOQ0KNFdtTnpGMnVORWpnZHNSUytCV3lKNTVJMnNPaUJHL2h6bGRZTDdaMGc3ZityWGhKZUFkcTNrTE9WZktNSTZhSg0KV0huWmk4djZ5c0hoTFcrckZreVBGTDhUWTZHS2tvSkg3NmZ1NHMxaVlRS0NBUUE1NUVoSnJGL0dtSzAxRzV5bg0KSXcvM1QrREJKWEYvYzdvSmJWZUdsL3ozVWNKL2kvcVA1V0x4NnA3Qlc2aUlNRERrZ1dZQ200OWVsU0dOTWp1dg0KaEltdjdwVUlIS0Zzam1YY2I5UGpNa1E0c2RLWGJ2QWV6MTBCSWM2L1BCRlVkTUNuM3k5RUwzbkZDNWZ1UFFHcQ0KbEY0MDg2aWJXMFFxdktXV1NjOE1ZalpDSGNFK05mRWZaRG1aVE1Uenk4eVJ3eUxGNUo3OGhKNFdBeEdTOUVDVQ0KUklOSi9kVlc5SDk1MnJYN1R4dzlVakxGeHRwN04zeTFNclBKVUV4UExrTks5UkNSNW1ZNExsU3BhelNDR0dTcA0KbzFMOW5FRnlUdVJHZHROVzZMTjM2bU5WV1prakpQaVlUYUpvUVd4b0JDRi9uNjlUNjNnQTJxYjBUaHhCWDU5eA0KWEtKakFvSUJBUUNyWUIvYjlkK1NJVGdwbGsrZWsyYWZXbndRcWFnWGVSVXFwUzdaL2crNnVvK3RtSWdlL1NLSA0KZ3NlT0ZyUk9qbGplekVQd3R3cmh3OVJxRHZZT2RQYyt5aTNBN3praksrUHl4NDloTyswZU05VisxM1dxTGd0OQ0KSzdZY3YxYWtXWStKNTBPTnFIdG82Y2xsWUdBVCs1cmx2Mm54czhQVEx6RU1PTkoxMXlDaEYzTWFGbGNkTzVKRQ0KR2dxNUxtV0N4R1pwRVZ4eWoyWmlDSHZOczFUQmVKWitTemM2bVcrVkNYclV0RXdzTnIrSENkRGZ3b09uckpCdg0KRStwTWtkZ3NBN045ZURxb1ZsOFFPNVJvM3BKUWdqM0hSS3V0bjB6eC9lQ1ZmL0EvM1Jta3BOSlpWMHpnak9BMQ0KNm5hdU1BWkdKWXJEeVpjRmlMbzRkN2RhYlhKUSsyRkJBb0lCQVFEaW9PMHV4NUZXSzJiV3kzVzkxRmpxMk05NA0KRXp1NnphRk52akJDalZhZ1pPRHZ4ck9NWHB0RG8vN3ZQK3E2K0Q0WXludDlQM2M0ekdaY3NiRFdFZ1ZaV2lCSw0KQ3ZQTFloZ2l4d0pxU3dadEtFanlWdzkvOUlWeEtNRWg4bGFkSnlibXB4aUpMcjllUlhhMjRyT0lnLzVhdzZPbQ0KQUp6OGpkeDhFM1RHb2hLZVBNSlF2M0I4QUkyVWZiYjhpOWxxcldIa3U4VVBRa1hSUlYxRUNYMXFGOGpjeUlJSA0KNlAyNlhKdGZOMDcxTzhRSTVVVG51N3QyaE13b2Rrd2ExdjBMMWljdnFUZEhoa1VXeWxFSEtLNVZObmllT1Uwag0KdlFVL0U3RUc0OWFMK3M2VC9VZmV3V2Z5Vm4xOFA3bmJHbThnUzZQdGp1ekE0Y0h0TFdpRUFHUTNmUE9pDQotLS0tLUVORCBSU0EgUFJJVkFURSBLRVktLS0tLQ0K"
    ca_cert_b64 = "LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tDQpNSUlGaVRDQ0EzR2dBd0lCQWdJVVdVdXlXS0NrMnEyc3Z0YjJERVM4cWNIWGZaOHdEUVlKS29aSWh2Y05BUUVMDQpCUUF3VkRFTE1Ba0dBMVVFQmhNQ1EwZ3hFekFSQmdOVkJBZ01DbE52YldVdFUzUmhkR1V4SVRBZkJnTlZCQW9NDQpHRWx1ZEdWeWJtVjBJRmRwWkdkcGRITWdVSFI1SUV4MFpERU5NQXNHQTFVRUF3d0ViWGxqWVRBZUZ3MHlNekE0DQpNakV4TURRME16aGFGdzB5TkRBNE1qQXhNRFEwTXpoYU1GUXhDekFKQmdOVkJBWVRBa05JTVJNd0VRWURWUVFJDQpEQXBUYjIxbExWTjBZWFJsTVNFd0h3WURWUVFLREJoSmJuUmxjbTVsZENCWGFXUm5hWFJ6SUZCMGVTQk1kR1F4DQpEVEFMQmdOVkJBTU1CRzE1WTJFd2dnSWlNQTBHQ1NxR1NJYjNEUUVCQVFVQUE0SUNEd0F3Z2dJS0FvSUNBUUREDQowUUNEbk9PTDF6YXNVUWsvNTVaMmZtY0Y4NmdYalo3NWZ1TnVGMWkxK0xoT3JkNUM2cWtrQkFqeFVZYW96ZHc3DQp1Z2xmMEJORlYrV1hTVjBIdEhXWVViK3FyODQ2OHI1YVRyME5ZWXMvMHFHemZGbU5EQ1ZCVGFTTWo3Y1NGRjYvDQowb2d6d0FUVFV2cHA1QzAxNkJvUk11c2JEaXh0bDEwcys3cG9scVEvY09IQnlYQW51ZWRQSGRiUUhYc29KQ1VmDQo0ZVEwalBDU0J6VjZGbGNZOUM3ODJaSnBIaFVnTy9QRDRDK2ZzanRGVy9QQTVhMWpzallUY3BRYmxOQ1VEejd4DQpDaWxzc3ZSR1k4b1ZJMEM4eGVuNTZVYjArRHVXOXFEVVk3ejZFaWthOXFNWDFXUmRVZDU2YUFlNFBqcHFJZjA4DQowai9TeC9XeVFvL3ZhUVRGWTZnVGI5MTFndStlLzRTSlBKZ3cxUExjeGFzNS9USFE5NUVtamRGSnJOQjg4c2lCDQpDeFEwYmVXdHdTWVFJZURUQlVJVkFOTk82WktXaHBaY05TdzN6ZlZ5Wm5zenF4QURRRlhWUnF2dFkzTEs0T25LDQplTmtjeDd2K3g4VFFWeXZuZFB1cFRNYWhxTno2WFl0WlRLaHFnVTd0QTdSVWJpZXhxVlRKVEo2Y1o4VEJQRUFFDQpZQ1lRYXY1aE5Zc2x5QmpUbVFwSEZnYThNYkVWM3VvOTZiZ3ZzNkgxNzhWeUk1K256WFFrY3ZUa1djZE5NaGN1DQp4TVZsZ09wamZQTzVJSTFnelp4QVJRZ2lmMW5vQVVWcUxwUWpqaXB2UkkyOEs3SmJOU25NVjdsUHoxbjhMUEc1DQpRd2x1N3dtVkdNUmprQjQrUkM2cXNmYSs0blpLb2VpczRLNjBrZXhBOHdJREFRQUJvMU13VVRBZEJnTlZIUTRFDQpGZ1FVZHBXOEtTeEhxci9xVE5NSG8yL3dmQVZNVXZnd0h3WURWUjBqQkJnd0ZvQVVkcFc4S1N4SHFyL3FUTk1IDQpvMi93ZkFWTVV2Z3dEd1lEVlIwVEFRSC9CQVV3QXdFQi96QU5CZ2txaGtpRzl3MEJBUXNGQUFPQ0FnRUF1aFpODQpvM2QrVzJBeldyM2RrbmVpSUIzVUZ2VEgzVEU3dDZKdVR0Y3NLVFh1dGYzNkVKRnhJZXBXTnF3cnlDSkJVSEZHDQphczA3YTJSaURTS1c0SzA0RmhyTmxsczN0cVo4T0hIeVFEbnc2RjZDRkQ4Y1NQa29aNkthQjFkeThsNHArSCtQDQp5emlaMkpJNzloYW1FZEVFVmZRYVhsdkxxUWh3anB2K0FqditYczJUSUtRZStqM29NV05wa1Z0NEd2SGhmS2wzDQpWUzBMSzVKN21NTWx1VUJhOVJWNnB5TmNRdXhDelFrc2FEUmRyQWZRQXBnc1RVVU1MQ3NKZndqamlkREtMZmNkDQplM2diTzZHK0krb0tWRFNOcWo0STN1YXljTTdxbHc1ZEZLU3dnM0c4cnZkdmlSSzBlRTY5bHA0MEk3L1NSSmovDQp1b1R6NjRtMlQzcStmMDNnS29HNUNZRnZiT05zd2FjSFo3L00zeW1KZnNXMVYrakRvWWlWMkczMkd2S0h3U0Q0DQpVTU92V2ZTQU9qKzZRK0srVEM3RU5lTU4xN3FrekNsdlc1MUtJb0h5b3dLR0t6Um5iVjlOZ3BmMWo0NFc0V1lhDQpmTlpPNE1Xa0k2c0dYcEVIQm02MTUyK01tMHFOYU9uaytxSVh2TUw4UHRmZjJobFdRcFA0K2hqeEJRbHJ0N09MDQppR29pamlobGFNeVZGQ05wcUZWZDU1S1I5ZDRqVXZnNGJITlM4UytWUkE3Z3J5cGl2UkxkTW9tSzFicjgzaEsrDQoxSWxxN1QxZU5tZlRtSytmYjhHeUNOaE91WGNvQnc1dk9NZDdpNGFmT0IyRzZFRG1td2tyM3hFbEI5dVZITS90DQpsQ2VpTlM2UlpxbjZGR0pJRjMwYXlaYXVGbnlNRVVYQWNKb1NqaUk9DQotLS0tLUVORCBDRVJUSUZJQ0FURS0tLS0t"

    get_privileges = ["page-all", "page-system-certmanager"]
    post_privileges = ["page-all", "page-system-certmanager"]
    put_privileges = ["page-all", "page-system-certmanager"]
    delete_privileges = ["page-all", "page-system-certmanager"]

    def sign_certificate_request(self, csr_cert, ca_cert, private_ca_key):
        """Copy certificate information form csr and sign it with ca key"""
        builder = (x509.CertificateBuilder().subject_name(
            csr_cert.subject
        ).issuer_name(
            ca_cert.subject
        ).public_key(
            csr_cert.public_key()
        ).serial_number(
            x509.random_serial_number()
        ).not_valid_before(
            datetime.utcnow()
        ).not_valid_after(
            # Our certificate will be valid for 10 days
            datetime.utcnow() + timedelta(days=60)
        ))

        for ext in csr_cert.extensions:
            if ext.oid.dotted_string == "2.5.29.17":
                builder = builder.add_extension(x509.extensions.SubjectAlternativeName(ext.value), ext.critical)
            elif ext.oid.dotted_string == "2.5.29.37":
                builder = builder.add_extension(x509.extensions.ExtendedKeyUsage(ext.value), ext.critical)
            elif ext.oid.dotted_string == "2.5.29.15":
                builder = builder.add_extension(ext.value, ext.critical)
            elif ext.oid.dotted_string == "2.5.29.19":
                builder = builder.add_extension(ext.value, ext.critical)
            elif ext.oid.dotted_string == "2.5.29.14":
                builder = builder.add_extension(ext.value, ext.critical)

        # Sign our certificate with our private key
        return builder.sign(private_ca_key, hashes.SHA256())


    def build_csr_cert_upload_request(self):
        """Create dynamic request data for csr cert upload"""
        return {'refid': self.csr_refid, 'crt': self.csr_cert}


    def build_invalid_csr_request_cert(self):
        """Create dynamic request data for csr cert upload"""
        return {'refid': self.csr_refid, 'crt': "YWJjZA"}


    def build_invalid_csr_request_crt_prv_no_match(self):
        """Create dynamic request data for csr cert upload"""
        return {'refid': self.csr_refid, 'crt': CRT}


    def build_invalid_csr_request_prv_not_allow_in_csr(self):
        """Create dynamic request data for csr cert upload"""
        return {'refid': self.csr_refid, 'crt': self.csr_cert, 'prv': PRV}


    def build_invalid_crt_prv_request_cert(self):
        """Create dynamic request data for csr cert upload"""
        return {'refid': self.csr_refid, 'crt': "YWJjZA", 'prv': PRV}


    def build_invalid_crt_prv_request_crt_prv_no_match_1(self):
        """Create dynamic request data for csr cert upload"""
        return {'refid': self.csr_refid, 'prv': PRV}


    def build_invalid_crt_prv_request_crt_prv_no_match_2(self):
        """Create dynamic request data for csr cert upload"""
        return {'refid': self.csr_refid, 'crt': CRT}


    def build_invalid_crt_prv_request_crt_prv_no_match_3(self):
        """Create dynamic request data for csr cert upload"""
        return {'refid': self.csr_refid, 'crt': self.csr_cert, 'prv': PRV}


    def build_invalid_crt_prv_request_encrypted_prv(self):
        """Create dynamic request data for csr cert upload"""
        return {'refid': self.csr_refid, 'prv': "LS0tLS1CRUdJTiBFTkNSWVBURUQgUFJJVkFURSBLRVktLS0tLQ"}


    def process_csr(self):
        """Sign CSR with local ca to upload certificate"""
        self.csr_refid = self.last_response['data']['refid']
        csr_data = self.last_response['data']['csr']

        csr_pem = base64.b64decode(csr_data)
        csr = x509.load_pem_x509_csr(csr_pem)

        ca_key = serialization.load_pem_private_key(base64.b64decode(self.ca_key_b64), None)
        ca_cert = x509.load_pem_x509_certificate(base64.b64decode(self.ca_cert_b64))

        cert = self.sign_certificate_request(csr, ca_cert, ca_key)
        self.csr_cert = str(base64.b64encode(cert.public_bytes(serialization.Encoding.PEM)), encoding='utf-8')

        #print("csr_refid:", self.csr_refid)
        #print("csr_cert:", self.csr_cert)

    def get_certificate_assertions(self):
        """Checks if get certificate result is correct"""

        cert_ass_done = {}
        cert_ass_done["webcfg"] = False
        cert_ass_done["e2etest"] = False
        cert_ass_done["intcertrsa"] = False
        cert_ass_done["intcsrrsa"] = False
        cert_ass_done["signprv"] = False
        cert_ass_done["signnoprv"] = False

        for cert in self.last_response['data']:
            if cert["descr"].startswith('webConfigurator default'):
                cert_ass_done["webcfg"] = True
                if not cert["crt"].startswith('LS0tLS1C'):
                    raise AssertionError(f"expect 'crt' in 'webcfg' certificate: start with 'LS0tLS1C', current: '{cert['crt']}'")
                if not cert["keyavailable"]:
                    raise AssertionError(f"expect 'keyavailable' in 'webcfg' certificate: 'True', current: '{cert['keyavailable']}'")
                if not cert["subject"].startswith('O=pfSense webConfigurator Self-Signed Certificate, CN=pfSense'):
                    raise AssertionError(f"expect 'subject' in 'webcfg' certificate: start with 'O=pfSense webConfigurator Self-Signed Certificate, CN=pfSense', current: '{cert['subject']}'")
                if not cert["issuer"].startswith('O=pfSense webConfigurator Self-Signed Certificate, CN=pfSense'):
                    raise AssertionError(f"expect 'issuer' in 'webcfg' certificate: start with 'O=pfSense webConfigurator Self-Signed Certificate, CN=pfSense', current: '{cert['issuer']}'")
                if cert["certtype"] != 'self-signed':
                    raise AssertionError(f"expect 'certtype' in 'webcfg' certificate: 'self-signed', current: '{cert['certtype']}'")
                if cert["iscacert"]:
                    raise AssertionError(f"expect 'iscacert' in 'webcfg' certificate: 'False', current: '{cert['iscacert']}'")
                if not cert["isservercert"]:
                    raise AssertionError(f"expect 'isservercert' in 'webcfg' certificate: 'True', current: '{cert['isservercert']}'")
                if cert["isrevoked"]:
                    raise AssertionError(f"expect 'isrevoked' in 'webcfg' certificate: 'False', current: '{cert['isrevoked']}'")
                if not 'webConfigurator' in cert["inuse"]:
                    raise AssertionError(f"expect 'inuse' in 'webcfg' certificate: containes 'webConfigurator', current: '{cert['inuse']}'")
                if not datetime.fromisoformat(cert["validfrom"]).astimezone(pytz.utc) < datetime.now(pytz.utc):
                    raise AssertionError(f"expect 'validfrom' in 'webcfg' certificate: < '{datetime.now(pytz.utc)}', current: '{datetime.fromisoformat(cert['validfrom']).astimezone(pytz.utc)}'")
                if not datetime.fromisoformat(cert["validto"]).astimezone(pytz.utc) > datetime.now(pytz.utc):
                    raise AssertionError(f"expect 'validto' in 'webcfg' certificate: > '{datetime.now(pytz.utc)}', current: '{datetime.fromisoformat(cert['validto']).astimezone(pytz.utc)}'")
                if not len(cert["serial"]) > 6:
                    raise AssertionError(f"expect 'serial' in 'webcfg' certificate: > len 6, current: '{cert['serial']}'")
                if cert["sigtype"] != 'RSA-SHA256':
                    raise AssertionError(f"expect 'sigtype' in 'webcfg' certificate: RSA-SHA256, current: '{cert['sigtype']}'")
                if not cert["altnames"][0]["dns"].startswith('pfSense-'):
                    raise AssertionError(f"expect 'altnames' in 'webcfg' certificate: 'dns' starts with 'pfSense-', current: '{cert['altnames']}'")
                if not 'Digital Signature' in cert["keyusage"]:
                    raise AssertionError(f"expect 'keyusage' in 'webcfg' certificate: contains 'Digital Signature', current: '{cert['keyusage']}'")
                if not 'Digital Signature' in cert["keyusage"]:
                    raise AssertionError(f"expect 'keyusage' in 'webcfg' certificate: contains 'Key Encipherment', current: '{cert['keyusage']}'")
                if not 'TLS Web Server Authentication' in cert["extendedkeyusage"]:
                    raise AssertionError(f"expect 'extendedkeyusage' in 'webcfg' certificate: contains 'TLS Web Server Authentication', current: '{cert['extendedkeyusage']}'")
                if not 'TLS Web Client Authentication' in cert["extendedkeyusage"]:
                    raise AssertionError(f"expect 'extendedkeyusage' in 'webcfg' certificate: contains 'TLS Web Client Authentication', current: '{cert['extendedkeyusage']}'")
                if not 'IP Security IKE Intermediate' in cert["extendedkeyusage"]:
                    raise AssertionError(f"expect 'extendedkeyusage' in 'webcfg' certificate: contains 'IP Security IKE Intermediate', current: '{cert['extendedkeyusage']}'")
                if not len(cert["hash"]) > 4:
                    raise AssertionError(f"expect 'hash' in 'webcfg' certificate: > len 4, current: '{cert['hash']}'")
                if not len(cert["subjectkeyid"]) > 10:
                    raise AssertionError(f"expect 'subjectkeyid' in 'webcfg' certificate: > len 10, current: '{cert['subjectkeyid']}'")
                if not len(cert["authoritykeyid"]) > 10:
                    raise AssertionError(f"expect 'authoritykeyid' in 'webcfg' certificate: > len 10, current: '{cert['authoritykeyid']}'")
                if cert["totallifetime"] != 398:
                    raise AssertionError(f"expect 'totallifetime' in 'webcfg' certificate: '398', current: '{cert['totallifetime']}'")
                if not cert["lifetimeremaining"] > 100:
                    raise AssertionError(f"expect 'lifetimeremaining' in 'webcfg' certificate: > 100, current: '{cert['lifetimeremaining']}'")
                if cert["keytype"] != "RSA":
                    raise AssertionError(f"expect 'keytype' in 'webcfg' certificate: RSA, current: '{cert['keytype']}'")
                if not cert["keylen"] >= 2048:
                    raise AssertionError(f"expect 'keylen' in 'webcfg' certificate: >= 2048, current: '{cert['keylen']}'")
                if 'prv' in cert:
                    raise AssertionError(f"expect 'prv' in 'webcfg' certificate: not available, current: '{cert['prv']}'")
            elif cert["descr"].startswith('E2E Test'):
                cert_ass_done["e2etest"] = True
                if cert["certtype"] != 'self-signed':
                    raise AssertionError(f"expect 'certtype' in 'e2etest' certificate: 'self-signed', current: '{cert['certtype']}'")
                if cert["isservercert"]:
                    raise AssertionError(f"expect 'isservercert' in 'e2etest' certificate: 'False', current: '{cert['isservercert']}'")
                e2etest_valid_to = pytz.utc.localize(datetime(3020, 1, 30, 18, 30, 2, 0))
                if not datetime.fromisoformat(cert["validto"]).astimezone(pytz.utc) == e2etest_valid_to:
                    raise AssertionError(f"expect 'validto' in 'e2etest' certificate: > '{e2etest_valid_to}', current: '{datetime.fromisoformat(cert['validto']).astimezone(pytz.utc)}'")
                if 'prv' in cert:
                    raise AssertionError(f"expect 'prv' in 'e2etest' certificate: not available, current: '{cert['prv']}'")
            elif cert["descr"].startswith('INTERNAL_CERT_RSA'):
                cert_ass_done["intcertrsa"] = True
                if cert["certtype"] != 'certificate-referenced-ca':
                    raise AssertionError(f"expect 'certtype' in 'intcertrsa' certificate: 'certificate-referenced-ca', current: '{cert['certtype']}'")
                if len(cert["caref"]) != 13:
                    raise AssertionError(f"expect 'caref' in 'intcertrsa' certificate: len != 13, current: '{cert['caref']}'")
                if not cert["isservercert"]:
                    raise AssertionError(f"expect 'isservercert' in 'intcertrsa' certificate: 'True', current: '{cert['isservercert']}'")
                if cert["altnames"][0]["dns"] != 'test-altname.example.com':
                    raise AssertionError(f"expect 'altnames' in 'intcertrsa' certificate: 'dns' is 'test-altname.example.com', current: '{cert['altnames']}'")
                if cert["altnames"][1]["ip"] != '1.1.1.1':
                    raise AssertionError(f"expect 'altnames' in 'intcertrsa' certificate: 'ip' is '1.1.1.1', current: '{cert['altnames']}'")
                if cert["altnames"][2]["uri"] != 'http://example.com/example/uri':
                    raise AssertionError(f"expect 'altnames' in 'intcertrsa' certificate: 'uri' is 'http://example.com/example/uri', current: '{cert['altnames']}'")
                if cert["altnames"][3]["email"] != 'example@example.com':
                    raise AssertionError(f"expect 'altnames' in 'intcertrsa' certificate: 'email' is 'example@example.com', current: '{cert['altnames']}'")
                if 'prv' in cert:
                    raise AssertionError(f"expect 'prv' in 'e2etest' certificate: not available, current: '{cert['prv']}'")
            elif cert["descr"].startswith('INTERNAL_CSR_RSA'):
                cert_ass_done["intcsrrsa"] = True
                if cert["certtype"] != 'certificate-signing-request':
                    raise AssertionError(f"expect 'certtype' in 'intcsrrsa' certificate: 'certificate-signing-request', current: '{cert['certtype']}'")
                if not cert["csr"].startswith('LS0tLS1C'):
                    raise AssertionError(f"expect 'csr' in 'intcsrrsa' certificate: start with 'LS0tLS1C', current: '{cert['csr']}'")
                if not cert["keyavailable"]:
                    raise AssertionError(f"expect 'keyavailable' in 'intcsrrsa' certificate: 'True', current: '{cert['keyavailable']}'")
                if cert["subject"] != 'ST=Utah, OU=IT, O=Test Company, L=Salt Lake City, CN=internal-csr-e2e-test.example.com, C=US':
                    raise AssertionError(f"expect 'subject' in 'intcsrrsa' certificate: 'ST=Utah, OU=IT, O=Test Company, L=Salt Lake City, CN=internal-csr-e2e-test.example.com, C=US' current: '{cert['subject']}'")
            elif cert["descr"].startswith('SIGNING_CERT_RSA_NOPRV'):
                cert_ass_done["signnoprv"] = True
                if cert["certtype"] != 'certificate-referenced-ca':
                    raise AssertionError(f"expect 'certtype' in 'signnoprv' certificate: 'certificate-referenced-ca', current: '{cert['certtype']}'")
                if cert["keyavailable"]:
                    raise AssertionError(f"expect 'keyavailable' in 'signnoprv' certificate: 'False', current: '{cert['keyavailable']}'")
                if cert["subject"] != 'ST=California, O=My Company, L=San Francisco, CN=mysite.com, C=US':
                    raise AssertionError(f"expect 'subject' in 'signnoprv' certificate: 'ST=California, O=My Company, L=San Francisco, CN=mysite.com, C=US' current: '{cert['subject']}'")
            elif cert["descr"].startswith('SIGNING_CERT_RSA_PRV'):
                cert_ass_done["signprv"] = True
                if cert["certtype"] != 'certificate-referenced-ca':
                    raise AssertionError(f"expect 'certtype' in 'signprv' certificate: 'certificate-referenced-ca', current: '{cert['certtype']}'")
                if not cert["keyavailable"]:
                    raise AssertionError(f"expect 'keyavailable' in 'signprv' certificate: 'True', current: '{cert['keyavailable']}'")

        for key in cert_ass_done:
            if not cert_ass_done[key]:
                raise AssertionError(f"no certificate found for '{key}'")


    def get_certificate_prv(self):
        """Checks if get certificate return private key"""
        cert_ass_done = {}
        cert_ass_done["webcfg"] = False
        cert_ass_done["e2etest"] = False
        cert_ass_done["intcertrsa"] = False
        cert_ass_done["signnoprv"] = False

        for cert in self.last_response['data']:
            if cert["descr"].startswith('webConfigurator default'):
                cert_ass_done["webcfg"] = True
                if not cert['prv'].startswith('LS0tLS1C'):
                    raise AssertionError(f"expect 'prv' in 'webcfg' certificate: starts with 'LS0tLS1C', current: '{cert['prv']}'")
            elif cert["descr"].startswith('E2E Test'):
                cert_ass_done["e2etest"] = True
                if not cert['prv'].startswith('LS0tLS1C'):
                    raise AssertionError(f"expect 'prv' in 'e2etest' certificate: starts with 'LS0tLS1C', current: '{cert['prv']}'")
            elif cert["descr"].startswith('INTERNAL_CERT_RSA'):
                cert_ass_done["intcertrsa"] = True
                if not cert['prv'].startswith('LS0tLS1C'):
                    raise AssertionError(f"expect 'prv' in 'intcertrsa' certificate: starts with 'LS0tLS1C', current: '{cert['prv']}'")
            elif cert["descr"].startswith('SIGNING_CERT_RSA_NOPRV'):
                cert_ass_done["signnoprv"] = True
                if 'prv' in cert:
                    raise AssertionError(f"expect 'prv' in 'signnoprv' certificate: not available, current: '{cert['prv']}'")

        for key in cert_ass_done:
            if not cert_ass_done[key]:
                raise AssertionError(f"no certificate found for '{key}'")


    def build_req_data_csr_for_signing_key(self):
        prv_obj = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
        )

        csr_obj = x509.CertificateSigningRequestBuilder().subject_name(x509.Name([
            x509.NameAttribute(NameOID.COUNTRY_NAME, u"US"),
            x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, u"California"),
            x509.NameAttribute(NameOID.LOCALITY_NAME, u"San Francisco"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, u"My Company"),
            x509.NameAttribute(NameOID.COMMON_NAME, u"mysite.com"),
        ])).sign(prv_obj, hashes.SHA256())

        csr = base64.b64encode(csr_obj.public_bytes(serialization.Encoding.PEM)).decode()
        prv = base64.b64encode(prv_obj.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.TraditionalOpenSSL, serialization.NoEncryption())).decode()

        data = {'method': 'sign',
                           'descr': 'SIGNING_CERT_RSA_PRV',
                           'caref': self.caref,
                           'keytype': 'RSA',
                           'keylen': 2048,
                           'digest_alg': 'sha256',
                           'lifetime': 3650,
                           'type': 'server',
                           'csr': csr,
                           'prv': prv,
                           'altnames': [
                               {'dns': 'est-altname.example.com'},
                               {'ip': '1.1.1.1'},
                               {'uri': 'http://example.com/example/uri'},
                               {'email': 'example@example.com'}
                           ]}
        return data


    def build_req_data_csr_for_signing(self):
        data = self.build_req_data_csr_for_signing_key()
        data['descr'] = 'SIGNING_CERT_RSA_NOPRV'
        data.pop('prv')
        return data


    def build_req_data_csr_for_signing_check_csr_prv_match(self):
        data = self.build_req_data_csr_for_signing_key()
        data['prv'] = PRV
        return data


    def build_req_data_csr_for_signing_check_invalid_prv(self):
        data = self.build_req_data_csr_for_signing_key()
        data['prv'] = CRT
        return data


    def build_req_data_csr_for_signing_check_invalid_csr(self):
        data = self.build_req_data_csr_for_signing_key()
        data['csr'] = CRT
        return data


    get_tests = [
        {
            "name": "Read system certificates",
            "post_test_callable":"get_certificate_assertions"
        },
        {
            "name": "Disable API scrubbing sensitive data to get the private key",
            "method": "PUT",
            "uri": "/api/v1/system/api",
            "req_data": {"scrubbing_sensitive_data": False}
        },
        {
            "name": "Check if private key prv is present",
            "post_test_callable":"get_certificate_prv"
        },
        {
            "name": "Re-enable API scrubbing sensitive data to be secure again",
            "method": "PUT",
            "uri": "/api/v1/system/api",
            "req_data": {"scrubbing_sensitive_data": True}
        }
    ]
    post_tests = [
        {
            "name": "Create RSA internal CA",
            "uri": "/api/v1/system/ca",
            "no_caref": True,  # Prevents the overriden post_post() method from auto-adding the created CA ref ID
            "req_data": {
                "method": "internal",
                "descr": "INTERNAL_CA_RSA",
                "trust": True,
                "keytype": "RSA",
                "keylen": 2048,
                "digest_alg": "sha256",
                "lifetime": 3650,
                "dn_commonname": "internal-ca-e2e-test.example.com",
                "dn_country": "US",
                "dn_city": "Salt Lake City",
                "dn_state": "Utah",
                "dn_organization": "Test Company",
                "dn_organizationalunit": "IT"
            },
        },
        {
            "name": "Import an existing PEM certificate",
            "req_data": {
                "method": "existing",
                "crt": CRT,
                "prv": PRV,
                "descr": "E2E Test",
                "active": False
            }
        },
        {
            "name": "Create internal certificate with RSA key",
            "req_data": {
                "method": "internal",
                "descr": "INTERNAL_CERT_RSA",
                "keytype": "RSA",
                "keylen": 2048,
                "digest_alg": "sha256",
                "lifetime": 3650,
                "dn_commonname": "internal-cert-e2e-test.example.com",
                "dn_country": "US",
                "dn_city": "Salt Lake City",
                "dn_state": "Utah",
                "dn_organization": "Test Company",
                "dn_organizationalunit": "IT",
                "type": "server",
                "altnames": [
                    {"dns": "test-altname.example.com"},
                    {"ip": "1.1.1.1"},
                    {"uri": "http://example.com/example/uri"},
                    {"email": "example@example.com"}
                ]
            }
        },
        {
            "name": "Check method requirement",
            "status": 400,
            "return": 1031
        },
        {
            "name": "Check unsupported method",
            "status": 400,
            "return": 1032,
            "req_data": {"method": "INVALID_METHOD"}
        },
        {
            "name": "Check description requirement",
            "status": 400,
            "return": 1002,
            "req_data": {"method": "internal"}
        },
        {
            "name": "Check description character validation",
            "status": 400,
            "return": 1037,
            "req_data": {"method": "internal", "descr": "<>?&>"}
        },
        {
            "name": "Check certificate requirement with existing method",
            "status": 400,
            "return": 1003,
            "req_data": {"method": "existing", "descr": "TestCA"}
        },
        {
            "name": "Check encrypted key rejection",
            "status": 400,
            "return": 1036,
            "req_data": {"method": "existing", "descr": "TestCA", "crt": CRT, "prv": "RU5DUllQVEVECg=="}
        },
        {
            "name": "Check certificate key matching with existing method",
            "status": 400,
            "return": 1049,
            "req_data": {"method": "existing", "descr": "TestCA", "crt": CRT, "prv": "INVALID KEY"}
        },
        {
            "name": "Check signing CA reference ID requirement for internal method",
            "status": 400,
            "return": 1047,
            "no_caref": True,  # Prevents the overriden post_post() method from auto-adding the created CA ref ID
            "req_data": {"method": "internal", "descr": "TestCA"}
        },
        {
            "name": "Check non-existing signing CA reference ID for internal method",
            "status": 400,
            "return": 1048,
            "no_caref": True,  # Prevents the overriden post_post() method from auto-adding the created CA ref ID
            "req_data": {"method": "internal", "descr": "TestCA", "caref": "invalid"}
        },
        {
            "name": "Check key type requirement for internal method",
            "status": 400,
            "return": 1038,
            "req_data": {"method": "internal", "descr": "TestCA"}
        },
        {
            "name": "Check unknown key type for internal method",
            "status": 400,
            "return": 1039,
            "req_data": {"method": "internal", "descr": "TestCA", "keytype": "invalid"}
        },
        {
            "name": "Check key length requirement for internal method",
            "status": 400,
            "return": 1040,
            "req_data": {"method": "internal", "descr": "TestCA", "keytype": "RSA"}
        },
        {
            "name": "Check unknown key length for internal method",
            "status": 400,
            "return": 1041,
            "req_data": {"method": "internal", "descr": "TestCA", "keytype": "RSA", "keylen": "invalid"}
        },
        {
            "name": "Check EC name requirement for internal method",
            "status": 400,
            "return": 1042,
            "req_data": {"method": "internal", "descr": "TestCA", "keytype": "ECDSA"}
        },
        {
            "name": "Check unknown EC name for internal method",
            "status": 400,
            "return": 1043,
            "req_data": {"method": "internal", "descr": "TestCA", "keytype": "ECDSA", "ecname": "invalid"}
        },
        {
            "name": "Check digest algorithm requirement for internal method",
            "status": 400,
            "return": 1044,
            "req_data": {"method": "internal", "descr": "TestCA", "keytype": "RSA", "keylen": 2048}
        },
        {
            "name": "Check unknown digest algorithm for internal method",
            "status": 400,
            "return": 1045,
            "req_data": {"method": "internal", "descr": "TestCA", "keytype": "ECDSA", "ecname": "prime256v1",
                        "digest_alg": "invalid"}
        },
        {
            "name": "Check lifetime maximum constraint for internal method",
            "status": 400,
            "return": 1046,
            "req_data": {"method": "internal", "descr": "TestCA", "keytype": "ECDSA", "ecname": "prime256v1",
                        "digest_alg": "sha256", "lifetime": 50000}
        },
        {
            "name": "Check common name required for internal method",
            "status": 400,
            "return": 1052,
            "req_data": {"method": "internal", "descr": "TestCA", "keytype": "ECDSA", "ecname": "prime256v1",
                        "digest_alg": "sha256", "lifetime": 365}
        },
        {
            "name": "Check unknown country for internal method",
            "status": 400,
            "return": 1051,
            "req_data": {"method": "internal", "descr": "TestCA", "keytype": "ECDSA", "ecname": "prime256v1",
                        "digest_alg": "sha256", "lifetime": 365, "dn_commonname": "test.example.com",
                        "dn_country": "invalid"}
        },
        {
            "name": "Check type requirement for internal method",
            "status": 400,
            "return": 1053,
            "req_data": {"method": "internal", "descr": "TestCA", "keytype": "ECDSA", "ecname": "prime256v1",
                        "digest_alg": "sha256", "lifetime": 365, "dn_commonname": "test.example.com",
                        "dn_country": "US"}
        },
        {
            "name": "Check type choice constraint for internal method",
            "status": 400,
            "return": 1054,
            "req_data": {"method": "internal", "descr": "TestCA", "keytype": "ECDSA", "ecname": "prime256v1",
                        "digest_alg": "sha256", "lifetime": 365, "dn_commonname": "test.example.com",
                        "dn_country": "US", "type": "INVALID"}
        },
        {
            "name": "Check invalid altnames data type for internal method",
            "status": 400,
            "return": 1055,
            "req_data": {"method": "internal", "descr": "TestCA", "keytype": "ECDSA", "ecname": "prime256v1",
                        "digest_alg": "sha256", "lifetime": 365, "dn_commonname": "test.example.com",
                        "dn_country": "US", "type": "user", "altnames": False}
        },
        {
            "name": "Check invalid altname type for internal method",
            "status": 400,
            "return": 1056,
            "req_data": {"method": "internal", "descr": "TestCA", "keytype": "ECDSA", "ecname": "prime256v1",
                        "digest_alg": "sha256", "lifetime": 365, "dn_commonname": "test.example.com",
                        "dn_country": "US", "type": "user", "altnames": [{"INVALID": "test"}]}
        },
        {
            "name": "Check DNS altname type validation for internal method",
            "status": 400,
            "return": 1057,
            "req_data": {"method": "internal", "descr": "TestCA", "keytype": "ECDSA", "ecname": "prime256v1",
                        "digest_alg": "sha256", "lifetime": 365, "dn_commonname": "test.example.com",
                        "dn_country": "US", "type": "user", "altnames": [{"dns": "!@#BADFQDN#@!"}]}
        },
        {
            "name": "Check IP altname type validation for internal method",
            "status": 400,
            "return": 1058,
            "req_data": {"method": "internal", "descr": "TestCA", "keytype": "ECDSA", "ecname": "prime256v1",
                        "digest_alg": "sha256", "lifetime": 365, "dn_commonname": "test.example.com",
                        "dn_country": "US", "type": "user", "altnames": [{"ip": "INVALID IP"}]}
        },
        {
            "name": "Check URI altname type validation for internal method",
            "status": 400,
            "return": 1059,
            "req_data": {"method": "internal", "descr": "TestCA", "keytype": "ECDSA", "ecname": "prime256v1",
                        "digest_alg": "sha256", "lifetime": 365, "dn_commonname": "test.example.com",
                        "dn_country": "US", "type": "user", "altnames": [{"uri": "INVALID URI"}]}
        },
        {
            "name": "Check email altname type validation for internal method",
            "status": 400,
            "return": 1059,
            "req_data": {"method": "internal", "descr": "TestCA", "keytype": "ECDSA", "ecname": "prime256v1",
                        "digest_alg": "sha256", "lifetime": 365, "dn_commonname": "test.example.com",
                        "dn_country": "US", "type": "user", "altnames": [{"email": "#@!INVALIDEMAIL!@#"}]}
        },
        {
            "name": "Create a csr with RSA key",
            "post_test_callable": "process_csr",
            "req_data": {
                "method": "external",
                "descr": "INTERNAL_CSR_RSA",
                "keytype": "RSA",
                "keylen": 2048,
                "digest_alg": "sha256",
                "dn_commonname": "internal-csr-e2e-test.example.com",
                "dn_country": "US",
                "dn_city": "Salt Lake City",
                "dn_state": "Utah",
                "dn_organization": "Test Company",
                "dn_organizationalunit": "IT",
                "type": "server",
                "altnames": [
                    {
                        "dns": "test-altname.example.com"
                    },
                    {
                        "ip": "1.1.1.1"
                    },
                    {
                        "uri": "http://example.com/example/uri"
                    },
                    {
                        "email": "example@example.com"
                    }
                ]
            }
        },
        {
            "name": "Check validation of active csr creation",
            "status": 400,
            "return": 1095,
            "req_data": {
                "active": True,
                "method": "external",
                "descr": "INTERNAL_CSR_RSA",
                "keytype": "RSA",
                "keylen": 2048,
                "digest_alg": "sha256",
                "dn_commonname": "internal-csr-e2e-test.example.com",
                "dn_country": "US",
                "dn_city": "Salt Lake City",
                "dn_state": "Utah",
                "dn_organization": "Test Company",
                "dn_organizationalunit": "IT",
                "type": "server",
            }
        },
        {
            "name": "Sign CSR and store crt and prv",
            "req_data_callable": "build_req_data_csr_for_signing_key"
        },
        {
            "name": "Sign CSR and store crt",
            "req_data_callable": "build_req_data_csr_for_signing"
        },
        {
            "name": "Check validation of csr and prv match",
            "status": 400,
            "return": 1097,
            "req_data_callable": "build_req_data_csr_for_signing_check_csr_prv_match"
        },
        {
            "name": "Check validation of prv pem",
            "status": 400,
            "return": 1098,
            "req_data_callable": "build_req_data_csr_for_signing_check_invalid_prv"
        },
        {
            "name": "Check validation of csr pem",
            "status": 400,
            "return": 1099,
            "req_data_callable": "build_req_data_csr_for_signing_check_invalid_csr"
        },
        {
            "name": "Import existing pkcs12 file with key, cert and ca",
            "req_data": {
                "method": "existing",
                "descr": "PCKS12 Import 1",
                "format": "pkcs12",
                "pkcs12": "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",
                "import_cas": True,
                "password": "password",
            }
        },
        {
            "name": "Check pkcs12 password validation",
            "status": 400,
            "return": 1100,
            "req_data": {
                "method": "existing",
                "descr": "PCKS12 Import 1",
                "format": "pkcs12",
                "pkcs12": "MIIRGgIBAzCCENQGCSqGSIb3DQEHAaCCEMUEghDBMIIQvTCCCxIGCSqGSIb3DQEHBqCCCwMwggr/AgEAMIIK+AYJKoZIhvcNAQcBMFcGCSqGSIb3DQEFDTBKMCkGCSqGSIb3DQEFDDAcBAjA7PIOpkB/uQICTiAwDAYIKoZIhvcNAgkFADAdBglghkgBZQMEASoEEJPankZDsUUgQfKkjgrhOEWAggqQOGeFOt20u4xWzDjNxSWHAxf2wq1RajxWooU2UzY6Dm9PDO0QPsCMN1xMv8JPMHnIykZXOe9kn6hxG31XTsSOJL1gzhcPIhR5skq3O6Z7K8/0a8nvGprmF5bpjF2tT0wn3+D/Lt8G9Zl15oGePukYNjH70HTzxHJChDhkA8KW2wvwoRNCIzZFBZf5TyXlqVE9gjrrIccU/IkTIKaEFhqRiPyOoSzMN4pcxkmfshc2aiPYx+Lem+COIMYoHfOdGSUL+jWZjFSeXUTPeWNxi58/d40+FfTRg6viN1XZPHgd37evNj9trBDQ+Y006+4V/T8LbNLVxQQGUzu4Ky5Ch4Nki/Ahp9FheFOEeqKr83whm4U/SIduoqK4tHe3/wINQmsJRAGS0xf3I59ZWlUFs9dkVVxIzRXiRzjX/mbDRj96e5yQgsfkzNjJFzFE3jGglbFfxhtm39CJBQqk7GDeME5FYM4/E5KCkC4ueDhADekOmWkfj05Ed6NoTdEId/Z9AeeygVJ/HJDZ4ZdYju6jpNsusJNNd9ZaBK8hPZNklQ9N2D+RK/lyMG5aaQUGwrhwOUDHZqmlOK54b5COgd4t7qDS94jC1WfFh5QeFS/Qmxmu5W/neNSQNeB0BGeQOD63RKJdWHYN15PX9W58vkRNUhBv6+uMmxj4UJWRWkYjbZZmrGj973byV/hpLuKbv9vkWhVneriNMtg6iruFrVdLLxbwrB49WTaOmmIKVfxxljc0J0dvbaQDcJHyx+lenqf9+iLoBw14LImVPW3ei1v9hNxFJjCBhwFvgdCxEqaYwy4HMtWMBTWgVfGMpC4B3ND/fKelXiT1HnaanNbD5PH5rsnV3NCBqU4AWfI9qHHU1fgARPqGWUHPmVbegtjs9FSCESw+mjrxPZwFP4x9JEfmDpQ0t/CDySsSRyoV1OzkNvSIkGnLPTsgp+uUcmVqetUlZMDF8DkOFTM1UmpAbvqcinyGb6S0HXj31cBBEMWjJcXGOB914mqyk0XJ/UYOneB47qzYmZMwF1jLioXys7Kyb2V16SkEj64ZHfdW+XycU0ygSh+SS3vAOyT7fM4EPNHI102Fz5HpTkTXtWcvAqfGSgzKsC1PaQ3Uk7ZfZXaCZ7wgXkqBw5SMltCNFQ84K3r6Q7knyhpnnSPIti/1f2VeV0h68fe+ZH6t1Brxk6oUBDfU8NZ44nWS/B2jySu+L3TqIQbgoGFSOPwIndC8JQG7kD6KUd7yPji5XlvHeX2dE+F0ub3iLwpUN+RZCuD0mw7SWmpLSfncgvbOrnXTQDuaMIZ1q2nH43Uu8eagYfDORGgdDPiD9cuwN4s1kmnzNBY93LEHYeiuKHjGB8H8Bd/iW2x4ehXgqN6Jjj5ikHSoG8Zh67K1MWNdiecpj5Hb5r+owu2hf0uta3CisVhEXewx7OZFHIGmigCzuWfV++kTpaEna7LxHOvRVaLYGVvev6yv3uAHZjWdeVsBEkWSMcR2Qrt81OzegOIWUhrzjsx0Y4BQ1Kmr09D/WyTf8S8A2Yt+KqG2jaBJKIZ8bUF9oGPKjF/Y52mLlUU1kTy2D97grIeJKatKm42yrSKuTMKne6Nazo1zr7NCf+6bSmVFUeZdQzH3gxQyiUaGqu0p7t0bUcqQtnBrdGqxKbeu0B0NhJlLi7Dqn6RebsLAD22M6nMVWr3rsjszdY9y9+uRd5Uxqfa+CBUJngl1bu/g6f/3zPxqCs529a9ovbC92mE6KtPiS5qB6kR6RGex+qHzgg2d0Slrpp4pZouq1hGxCPa8aYRXPFV/eKJDVTXX2z1HJ74YX0rcTOGRkBwtfN8/v0+TPV7cWJxf+AQeD4B3Guf9PwxpocqQXLQgTlxqxA/yHAddgJtYKg5nIzLiR/0IKvOLBA2PpOA7SBIvW+DBXVFmYxss2okENO5JOCwO2VCP0BdFFQ0slgVgfd4QM2sxDZ/5bGgJF7vLKG6n5Ro2y0bLTEkIokL+i/DhWamhc3rN2+HsOGY/GR099Jo4U21cB5Wx8e8dHXbynpMzmKROrEO+5B/Co8mA/OSUTVL8hjSjD0sKJLH99sq2LAmQ6SBhByInNizbCdppXHxBMHcXrvT1wdIdPL67RTpFibfVlHtt1pww/W8wqoJQa/sAUo8b12ASuhRHT96S5VheqaUkVMOF9CbVhIc8PwLvD5YVDhTQxbxOlaAB6Ww874zr/1mQBg6kx6ebIHOrYEkm10ORKTthvsAYt/Ru8dnJsFa8X4rBjbOxj9BHY65jPSR0pE192g6T88rqwi6CkMFMLUC2txfPpKaBmdjwgkC1MApy14He1WTkgTV3WfhFL3PiIlN14bYrlgeUbTtmu3xsyllZgCHApvJXmJ0VLVBwdjmAPQH4znlIb84d8phptzAYcjCyzMFtLDhOzfsHjFw14zUWctnPvBGu3gwTwEUJ/l6zl2IUw0qUn5rDTeOQ3YxuDJbqiByZC1DvbAzrkXTHwUYuuzvqH6pnfGilmuGLL6/sHpzhxevnlRvcx1stShbG4odwYSq9oYCbPFyUtqpzZdSQ72ZRRz5arzfpdSjqFbA89jSnPUIlpyRZy8pOribxSs78COpAVG6JqWEpUa9rcXUANlLd3x+N48FNEQTd/OcteG5nEly8x4ouLQPJ/TS8kdudDzUTNdrqhFrJbChAw48+n0Md/TtmUvVlD1FC0jGb4Bz+ttptSmrlszYhvRRUo+oXkpAxTU/BUvuIDQn66Dc3GuhqV1KGKGFV1voq0jjWHI/Fx6luNZ8MPCVEfNT8u7rP9sraTM0jc5WnAhBajNM6vxxLPAlMMuhHEuWw8/u87TxBRWSUUOSmZjhaPpQaqrDNEPdpr8QURjgOp1vme+NEFR/GHBHLJ9nv1VZJQ0L8mMb6hvRqvwQsyle2tm/UJsRfbFiQtTAiCUl72KSk5cvc8xGnSNyCq2kMgWcTUN1AecSM0W9ralfvGc7Gv9ti3M730vtCGo7e5kWp6+MZ2Rae/XMKM3cIjS7SIG0pqInTD2ViuCFpyAeHo241qvUwEcBF8+7gsHy3jR+4QzPj7LDTzmg53UH0y0elpqapGjhUHhKxTFBrF5NcVTPKwXJqjhfhTvvfz50OwQBYJ0vZdH1oVT9sfUJQE+w4VIyW9QWtV+Rg08uuBrAhyJukzjaeFSpf+v3S3JpC1hXY+xGJTBh9CAbWfp12Okbm6e2Wx/xactmtmAEy9cWltv4bvMwPbIaWILRzioW/hPXcW2jsAg2EQcIxF/BEW8jykXE8YdbFpS0PD4hpvFwMS++kRB4yFoNx2c2bo9107jf6DKlne/Cz8dwYpWww9/M6++wwCb0flMMwIVZGak79FEtmvrdhat4ldFEVFJFKkmNxHpwdZCV9fwNoRX7/NHsPSehhiiVyN4MvlEep5WHRouYDardIIuwwH2qPmvBBM30g28T/oTIHK91HXn2+Y+JKNSY64BbqWocN10bl64hxiUElXfBF9mgYVlA35Vh9ThVf05QxhFyFI7IAyl6K0Oid90862NsIEzdVlP0Xdula+e5ST+9CBO0bJZtnQCKO9QpZnrkutXJHIlIfOwJ2J2vVh5bni/7dx6dttIzUjrQ0KDCCBaMGCSqGSIb3DQEHAaCCBZQEggWQMIIFjDCCBYgGCyqGSIb3DQEMCgECoIIFMTCCBS0wVwYJKoZIhvcNAQUNMEowKQYJKoZIhvcNAQUMMBwECK7kywEmL66PAgJOIDAMBggqhkiG9w0CCQUAMB0GCWCGSAFlAwQBKgQQNuKQQuRSKi/7OgoqBK8ubASCBNAzWxZtc/wKkyfbAU7ZBNcbHoVmJ9QNYqf+Noy1Kh9LqIdjyT0JUmek5q/Y+nY9tyhPPKCbEyH59qcjarlhgiblcCNlZk9otnmCTCvhzk7yUW+Ov/q6U9fps8utPJSF1NhooQ/c1/kWbN5kx3bRl7gyqXqx8b4vork4Zpuo4YLd03GbBk3Xz3mUdyMlfRbH7n4N3BdfyC7r0vehHPg+8veGx7ZHfSKqqUuDxUjVYBoYOq6dQplhiXFn/itHSFIBRv/Op+mqmrjW59tGkktdez8S1o0IUEeVXBwuESQZ4azsnphM5bVLEwlsTFZX0msbdAyH7+fKMsk0xKy6cQmYYq25z+vUnfpzcVI0Ur/63e3PjDpLMQH/MIk/5NDsPO6g35qgJx7WqPjS7rxHYgrKnfM7+vj+qUXlNFDOe9CCduaVYwG1pb5GaKBe1yyvvVg/ZKwFxKdtb8pbKzvXGN4qdrngLm6dQBj7S3N1V5cXqARuUU/vqbla7y0c6ZnmkXX7Sig9593q+MXDSAX3C02EqM1yg3HbRVGElCFS/Dtj4ppffFlhbq0j1awtrUbk0e1NHE1Tww+GToC94vKkCuvjgoMUccX1dTHsbdMdQeXtNh1XvtSWVlDaKllx3D9qBItZVqIQiAMZi7XqHnmW1p+AIlE0ecnhavC49QE+pcSlQitUs4ryO6b6vznzvVFJ+jIJaCF1o1COJHOEGgL3Iqsd6+u7Eie+YWDmVjVVbJAmNz0nRkJX+kwD6gH/hNPv1OuEmFvGgDkbCGPoWrC8o5vSZlyWbVWDwaX0qMne6//r1CmYElRLlPx0YHtZglfy5F/xNWtQLdidfmmkcFzwV3uQZfoG2dkXJfxIZXGX1fAb4FslCqEEU1j8sPx57+6aew1k5ny9rzUtxPjpdmJNGBbwjsRSmxxECm/Gi5y3Br9IB+ot98XKrmsXILtuWJuwYZfCaC7azcLwbSFRlhEHfY+YB+oiN2thMthkCX7jGNk/V0b6fvcitFU5Q2JcdjQ5ICi6WDtTaySL1+4KhEhzmsWeQW0EDOuBO23oSFwU3jW0TTDCbDwGs+WkQ4qFpo0zgd1SAS07M0/gTGw2my0/iS1rQ64dsacIAXSZJx0ZMB73DplVeUPborAArndDF3JQm/dSB7eoIcRypn/uQ3EfpaI7doBau13lUD8zyZbxVZuNfVxHZj5FLVfGk2gBkxGAHFn/Cz7aQKnMpcR8o7ECvtRNBjVIPWFg7CIGkg82fysMQHJcXmk/RXjuVn3RylK4jeHn14uTftI36h5Z8HzIydyxSsZAQMjwNPoePDXZBHK6DXk9Kmq8r0X+m77NE085YB7TzD6LlRtD/tw8VFjNgyFpu096CzzOAC9o+ZqEKor+1VWgQrp7jm3OtwjE2c3VeuGtWwuJR9YCbWmeVmlt71Oby3zYHbLfJa8JdjxDBjmRGd7zki8SnhuXw5iZL94RJeDtXPkkHEasxrU+ZaF99+Q4SR2l0uAW9G99GOJWAP5V6m34vcSKp6dj9QjKbAV5RZCnNRoyletR2EC5X5bP2FBbRARTyrWJg2oHaZsvSOwYs+1OD/n1zbyMjN+L70CtBzX1RynVcI4Whz5hKnxE7CLOJnqtMHP0FUPaZntjcdEKIwRFwjFEMB0GCSqGSIb3DQEJFDEQHg4AbQB5ACAAYwBlAHIAdDAjBgkqhkiG9w0BCRUxFgQUt9S61SKtligFtxGLPGwRdFDlNpcwPTAxMA0GCWCGSAFlAwQCAQUABCDevOBOi2r2PsjdBVcl0VxYf/JzAcMvoCiUp1+glPDfWgQIobZAs3G01Og=",
                "import_cas": True,
                "password": "password123",
            }
        },
        {
            "name": "Check pkcs12 data validation",
            "status": 400,
            "return": 1101,
            "req_data": {
                "method": "existing",
                "descr": "PCKS12 Import 1",
                "format": "pkcs12",
                "import_cas": True,
                "password": "password",
            }
        },
        {
            "name": "Check existing format validator",
            "status": 400,
            "return": 1102,
            "req_data": {
                "method": "existing",
                "descr": "PCKS12 Import 1",
                "format": "pkcs11",
                "pkcs12": "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",
                "import_cas": True,
                "password": "password",
            }
        },
        {
            "name": "Import existing key pair with encrypted key",
            "req_data": {
                "method": "existing",
                "descr": "Encrypted PEM Key Import 1",
                "format": "pem_encrypted_key",
                "crt": "LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCk1JSURPVENDQWlHZ0F3SUJBZ0lVQm96eUtTZmErMDhkVnc4VThYVmZBYkFqWUVVd0RRWUpLb1pJaHZjTkFRRUwKQlFBd0tqRUxNQWtHQTFVRUJoTUNWVk14R3pBWkJnTlZCQU1NRW0xNUlHbHVkR1Z5YldWa2FXRjBaU0JqWVRBZwpGdzB5TXpBNE1qWXhOekV6TXpkYUdBOHlNVEl6TURnd01qRTNNVE16TjFvd0h6RUxNQWtHQTFVRUJoTUNWVk14CkVEQU9CZ05WQkFNTUIyMTVJR05sY25Rd2dnRWlNQTBHQ1NxR1NJYjNEUUVCQVFVQUE0SUJEd0F3Z2dFS0FvSUIKQVFDcDJMeEYwQ1JsTkk4NnJmak9YNDNkOWhEdGtVdDFFQXZQblY1Q2JVZERiaG9ndjVBVERweHNhc3Jxb1R0OApYRlpheFB1K1dYcHRNUTVYSHZtRWtBYkw4aFEyVVNsOGxrSGYyRjRpTEM0LzY0MVIvMDlIL3V2eUJzMGdiUXdjCmNFMm5iWkl3VjZiQ3U4VlNXdStWU1RSa2ZoSk0xZnlKazN4Z1A2ZzFWU0U1MjlUS2ZKV1lSMVZiRmVkNGh3VXYKTnY0Q0Riem43ZEZNd0Y5dUxXS0Q1ZUtjR01sU3JIUEZhdlN4RlIwMjZQdmdoVGxzQ0h2bVdFcUZFRmJESzM5cwpSS21ESm5YMDR1enNxZ054NDlnaU1KQjkrWmZnK1VyRWZUS1BOSnFpcUI1bTdCMzBqa0xDb1l6VzJpWHVHcys1CmgrcmhUWUI2TThzUHZrdEIzWkRZNXArVkFnTUJBQUdqWURCZU1Bd0dBMVVkRXdFQi93UUNNQUF3RGdZRFZSMFAKQVFIL0JBUURBZ1dnTUIwR0ExVWREZ1FXQkJSOFdGc2FKNGRGSHg1U3FNZzdzWGdndEErU3ZqQWZCZ05WSFNNRQpHREFXZ0JUNU96WVNyUkFkSEh0clVWck9PMVpTOFc1Qk56QU5CZ2txaGtpRzl3MEJBUXNGQUFPQ0FRRUF0U2JICksydExIUThrRkt6YmVlaDNaUmxwMy9WcWM5UUZsckgzTkYvQVpiTnhDVUtDTWVFSEN5b2t5cXdhK3B2UjM3VlkKVitNaFYramlYeEdWVURRUUxkKzF2dGl1d2JTZVAxclFZbFdJeDREZlo0cHVkVEZ6MFZEQ1JaVThLYWRDbE9BQQpJU2plN3ZvUC9CZFRtWHkzVjR6MjUvV3B2WkZoOTNDOUNVcUloQ3ZLNnB4ZEtiZ2ZjcGdjWDJaUERqdkUwUmlMCjVFdURVdXJhTE0xbUdRUC9QODlVQURCZ0E5amFlRHN5MS83T2FNdWZTbGpKUkh6c0hvVlRORklxbVBlaWoxUmcKVlQ2dmhCbTJOV01BYXc1c09uWWtZWlE1V2RXbXdmVTRDRWt3ZHVYY3BoU3ZodFZHMHR1c0ViNVFRUytkTkllbApETGVlQ3pPT09sL0kvWmVLdlE9PQotLS0tLUVORCBDRVJUSUZJQ0FURS0tLS0tCg",
                "prv": "LS0tLS1CRUdJTiBFTkNSWVBURUQgUFJJVkFURSBLRVktLS0tLQpNSUlGTFRCWEJna3Foa2lHOXcwQkJRMHdTakFwQmdrcWhraUc5dzBCQlF3d0hBUUl3bk1kQ3NzUkpMNENBZ2dBCk1Bd0dDQ3FHU0liM0RRSUpCUUF3SFFZSllJWklBV1VEQkFFcUJCQksrd1p3U3phYU9KRkI2RUhTYzAydkJJSUUKME5XdHdOU1RQemV6UTk0NDA2ZzRnWjVnL2xyZTJ3K0g5TnlmNEhTa2QyRlRhQVEyNFBCMGZNV2o0WVlubisyaAprYW5FdjRIMWppNTRSWFJLc3I0L0hCMnJsZXlOSlBIWXIvZURra2hmejFUTDVBT3BxSGQvTUhDRGx3Y2d6R05uCjJvOFlnK0w2cWM4WmpWWEt3Vi9kdFNsUm5JZDM2TnJhbjRqdXBNVjVZUVZJK1VTUjhTTytBMkRZeGxDa1Vob1cKdExtdXNFOEFndTJaSWlXTzVtd1dYVlR1aDVIT0RhTlAyQnprbWZvZFVaOW5BTU9pMm5LK0tiTG9UWGJhblZsWgpQSW1HNnZvVmZscDltZk1mSVk3TEpaaEhNYUlNRDZNaVlHa2VEL3RIR1puTk1TbzQzOW5TcnBJQmNtYmY4WktICkllK2pnR3FaZ2RVT0dwZlliQ3RHb0lBNmgraEliWkRKeVJnZFZyb1pLWDlhQzFSM1A5bFByMk0yOW9MQ0NSci8KRUlNNU03b3Z3N0lkMmdobWRWVnM0M2FCcHV4QVU0allSK0YxbUd1QXFNM3ZZM0xHTi9VVzJHcEpFMC8vSWg5eQpJZld5akRISE5PMXU0eU0xODFEUHg5ZkhhSGQ5Ymk4K0dRK005U3RrVzk3andaR3NPUlpHd1lleXBvQnhYSlJvCjk3ODhEczFwZWJ1TVA4NFYxU3F4a0hORkZiWTJGRU1vZVJZT2Z2OG4zMFliek5zNC9senRaM0w0QnFndmFGQ3oKUGtCMUdNNkNIVkVFZThSY25FaXRBZDMxMmhCNXZ5cDlpbytvWTc5L2E3djFETk9FT3JWTmdSQXdjcGNHQUpyTAo1WVJDZGI1TVdlSGI4SjVYM1gvSlpOV0dsTko5bW5vM3JWRWVSZjdpRmZXb3NzajJsR1FqNm5CZ3RDdTZQRGJvCnJUbForNkFIdzZMNXFOZ053UGhORmpNNUxNN3hjV1JDM2NsSEk2LzRJKzF2RzU1T1BzUFhoNGZ6eVRPRzBsS2MKNjV2OU1VQVNtNWNNVlFkd3MrVWxlOEQxcnR5MEZDa2FvaVVFVmsyKzE2R1hLM1ZVTnY4c0RXaDBHRTZlWldxNwpSVWZkZFNFcDA3TTRLc0FsQ2RRVU0vc1VhcXZyQkROeGl5T3oyTGhhcEZjM3dhNnN1ZUJDa1o1TVBZRVZuUUlMCjVWb0lsM3ovZGwvalZFczdOTmRoYlRSM05xblVQcnQwb2MrVU42by8vcXBGWFBhU0toVVEyREZwS1RZc0dCM20KVDU4TDZnN1FMWnYwYzU4QW8wblZ0MlJXM1BNaFd3UXRCd0NvWXlRVUFKVVdUYUNsV283bjBkUSthNWpPVDBxUAo5V0Y4bWppOHRUQllBSXNPQUNGN0RlVEI2blVQM3VFRG4xNUJhalZCYVpMaWFPNWQxYWJMMlVvVWJ6QVVxbWVWCmdxRmdURHBBbE5na1gzcXZwN0ErTjVtM0MyN0JEaURTdS9ONzNHVFNEb09mOC9LR2J0Q3ZOd1ZSKzlJMXNEL00KOGROOEgrRTBsY0E1OWNlcXhrQXdpUVBTdXMyVkZVRkwxTHU4aHp6L0ZnUW1WVS9HS0hTMlo5L2FSSFg0WWljVQpQMld3WTJ0YXJBM2R6RU9VU1dEdGRGL1NvalIxbkg1UW5CcFVTc3pnSmYycFhVcWtUQUY4OGdxSStUeFZweU11Ck5LaEQ0UWJZaHpXalArdDZGb09yVDczWEpoZUdDcjBSRVQ0UjdvcWZxejNudHl5T0JpZ0VpREp1bnRBeUZpQ0gKNlpDNWkwUE8yLytPekQwb3NjOWhJS3VnK25DYUVWc1pXUEdkM09iNkxTVmJsRC9DZm52V1YrVDdYV2NXTXhEMwpUbzJHR1M0T1llUW5mVVhlZWFwM3F2ditvWC9XWHpWMXFXMGJESk4vejZxclo5WEYvcC9VdEE4Sm4vekUySnozClFiVkZEandWczU2N3VkTUxXd1p5dmxnd2RuL1BuUTQ2V3F5VU1kQlI0S0xzclVoSDhQV1dBdUFoSFN3R3JySnUKYWR6RWZFNTlQc0JrLzZ4MDdpQmMxMTNqK29RYXJ0b1dLM0lMOWNuRHFKUEJUQkxxeVVEaUlySW9rTTJRaS9TWQpyaGk1akRaTFVDSCtXRXFoeFJ3T0t4NkUzZ01EenRVanptSG5GMUZkUlVrRgotLS0tLUVORCBFTkNSWVBURUQgUFJJVkFURSBLRVktLS0tLQo",
                "password": "password",
            }
        },
        {
            "name": "Check wrong password for encrypted key",
            "status": 400,
            "return": 1103,
            "req_data": {
                "method": "existing",
                "descr": "Encrypted PEM Key Import 2",
                "format": "pem_encrypted_key",
                "crt": "LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCk1JSURPVENDQWlHZ0F3SUJBZ0lVQm96eUtTZmErMDhkVnc4VThYVmZBYkFqWUVVd0RRWUpLb1pJaHZjTkFRRUwKQlFBd0tqRUxNQWtHQTFVRUJoTUNWVk14R3pBWkJnTlZCQU1NRW0xNUlHbHVkR1Z5YldWa2FXRjBaU0JqWVRBZwpGdzB5TXpBNE1qWXhOekV6TXpkYUdBOHlNVEl6TURnd01qRTNNVE16TjFvd0h6RUxNQWtHQTFVRUJoTUNWVk14CkVEQU9CZ05WQkFNTUIyMTVJR05sY25Rd2dnRWlNQTBHQ1NxR1NJYjNEUUVCQVFVQUE0SUJEd0F3Z2dFS0FvSUIKQVFDcDJMeEYwQ1JsTkk4NnJmak9YNDNkOWhEdGtVdDFFQXZQblY1Q2JVZERiaG9ndjVBVERweHNhc3Jxb1R0OApYRlpheFB1K1dYcHRNUTVYSHZtRWtBYkw4aFEyVVNsOGxrSGYyRjRpTEM0LzY0MVIvMDlIL3V2eUJzMGdiUXdjCmNFMm5iWkl3VjZiQ3U4VlNXdStWU1RSa2ZoSk0xZnlKazN4Z1A2ZzFWU0U1MjlUS2ZKV1lSMVZiRmVkNGh3VXYKTnY0Q0Riem43ZEZNd0Y5dUxXS0Q1ZUtjR01sU3JIUEZhdlN4RlIwMjZQdmdoVGxzQ0h2bVdFcUZFRmJESzM5cwpSS21ESm5YMDR1enNxZ054NDlnaU1KQjkrWmZnK1VyRWZUS1BOSnFpcUI1bTdCMzBqa0xDb1l6VzJpWHVHcys1CmgrcmhUWUI2TThzUHZrdEIzWkRZNXArVkFnTUJBQUdqWURCZU1Bd0dBMVVkRXdFQi93UUNNQUF3RGdZRFZSMFAKQVFIL0JBUURBZ1dnTUIwR0ExVWREZ1FXQkJSOFdGc2FKNGRGSHg1U3FNZzdzWGdndEErU3ZqQWZCZ05WSFNNRQpHREFXZ0JUNU96WVNyUkFkSEh0clVWck9PMVpTOFc1Qk56QU5CZ2txaGtpRzl3MEJBUXNGQUFPQ0FRRUF0U2JICksydExIUThrRkt6YmVlaDNaUmxwMy9WcWM5UUZsckgzTkYvQVpiTnhDVUtDTWVFSEN5b2t5cXdhK3B2UjM3VlkKVitNaFYramlYeEdWVURRUUxkKzF2dGl1d2JTZVAxclFZbFdJeDREZlo0cHVkVEZ6MFZEQ1JaVThLYWRDbE9BQQpJU2plN3ZvUC9CZFRtWHkzVjR6MjUvV3B2WkZoOTNDOUNVcUloQ3ZLNnB4ZEtiZ2ZjcGdjWDJaUERqdkUwUmlMCjVFdURVdXJhTE0xbUdRUC9QODlVQURCZ0E5amFlRHN5MS83T2FNdWZTbGpKUkh6c0hvVlRORklxbVBlaWoxUmcKVlQ2dmhCbTJOV01BYXc1c09uWWtZWlE1V2RXbXdmVTRDRWt3ZHVYY3BoU3ZodFZHMHR1c0ViNVFRUytkTkllbApETGVlQ3pPT09sL0kvWmVLdlE9PQotLS0tLUVORCBDRVJUSUZJQ0FURS0tLS0tCg",
                "prv": "LS0tLS1CRUdJTiBFTkNSWVBURUQgUFJJVkFURSBLRVktLS0tLQpNSUlGTFRCWEJna3Foa2lHOXcwQkJRMHdTakFwQmdrcWhraUc5dzBCQlF3d0hBUUl3bk1kQ3NzUkpMNENBZ2dBCk1Bd0dDQ3FHU0liM0RRSUpCUUF3SFFZSllJWklBV1VEQkFFcUJCQksrd1p3U3phYU9KRkI2RUhTYzAydkJJSUUKME5XdHdOU1RQemV6UTk0NDA2ZzRnWjVnL2xyZTJ3K0g5TnlmNEhTa2QyRlRhQVEyNFBCMGZNV2o0WVlubisyaAprYW5FdjRIMWppNTRSWFJLc3I0L0hCMnJsZXlOSlBIWXIvZURra2hmejFUTDVBT3BxSGQvTUhDRGx3Y2d6R05uCjJvOFlnK0w2cWM4WmpWWEt3Vi9kdFNsUm5JZDM2TnJhbjRqdXBNVjVZUVZJK1VTUjhTTytBMkRZeGxDa1Vob1cKdExtdXNFOEFndTJaSWlXTzVtd1dYVlR1aDVIT0RhTlAyQnprbWZvZFVaOW5BTU9pMm5LK0tiTG9UWGJhblZsWgpQSW1HNnZvVmZscDltZk1mSVk3TEpaaEhNYUlNRDZNaVlHa2VEL3RIR1puTk1TbzQzOW5TcnBJQmNtYmY4WktICkllK2pnR3FaZ2RVT0dwZlliQ3RHb0lBNmgraEliWkRKeVJnZFZyb1pLWDlhQzFSM1A5bFByMk0yOW9MQ0NSci8KRUlNNU03b3Z3N0lkMmdobWRWVnM0M2FCcHV4QVU0allSK0YxbUd1QXFNM3ZZM0xHTi9VVzJHcEpFMC8vSWg5eQpJZld5akRISE5PMXU0eU0xODFEUHg5ZkhhSGQ5Ymk4K0dRK005U3RrVzk3andaR3NPUlpHd1lleXBvQnhYSlJvCjk3ODhEczFwZWJ1TVA4NFYxU3F4a0hORkZiWTJGRU1vZVJZT2Z2OG4zMFliek5zNC9senRaM0w0QnFndmFGQ3oKUGtCMUdNNkNIVkVFZThSY25FaXRBZDMxMmhCNXZ5cDlpbytvWTc5L2E3djFETk9FT3JWTmdSQXdjcGNHQUpyTAo1WVJDZGI1TVdlSGI4SjVYM1gvSlpOV0dsTko5bW5vM3JWRWVSZjdpRmZXb3NzajJsR1FqNm5CZ3RDdTZQRGJvCnJUbForNkFIdzZMNXFOZ053UGhORmpNNUxNN3hjV1JDM2NsSEk2LzRJKzF2RzU1T1BzUFhoNGZ6eVRPRzBsS2MKNjV2OU1VQVNtNWNNVlFkd3MrVWxlOEQxcnR5MEZDa2FvaVVFVmsyKzE2R1hLM1ZVTnY4c0RXaDBHRTZlWldxNwpSVWZkZFNFcDA3TTRLc0FsQ2RRVU0vc1VhcXZyQkROeGl5T3oyTGhhcEZjM3dhNnN1ZUJDa1o1TVBZRVZuUUlMCjVWb0lsM3ovZGwvalZFczdOTmRoYlRSM05xblVQcnQwb2MrVU42by8vcXBGWFBhU0toVVEyREZwS1RZc0dCM20KVDU4TDZnN1FMWnYwYzU4QW8wblZ0MlJXM1BNaFd3UXRCd0NvWXlRVUFKVVdUYUNsV283bjBkUSthNWpPVDBxUAo5V0Y4bWppOHRUQllBSXNPQUNGN0RlVEI2blVQM3VFRG4xNUJhalZCYVpMaWFPNWQxYWJMMlVvVWJ6QVVxbWVWCmdxRmdURHBBbE5na1gzcXZwN0ErTjVtM0MyN0JEaURTdS9ONzNHVFNEb09mOC9LR2J0Q3ZOd1ZSKzlJMXNEL00KOGROOEgrRTBsY0E1OWNlcXhrQXdpUVBTdXMyVkZVRkwxTHU4aHp6L0ZnUW1WVS9HS0hTMlo5L2FSSFg0WWljVQpQMld3WTJ0YXJBM2R6RU9VU1dEdGRGL1NvalIxbkg1UW5CcFVTc3pnSmYycFhVcWtUQUY4OGdxSStUeFZweU11Ck5LaEQ0UWJZaHpXalArdDZGb09yVDczWEpoZUdDcjBSRVQ0UjdvcWZxejNudHl5T0JpZ0VpREp1bnRBeUZpQ0gKNlpDNWkwUE8yLytPekQwb3NjOWhJS3VnK25DYUVWc1pXUEdkM09iNkxTVmJsRC9DZm52V1YrVDdYV2NXTXhEMwpUbzJHR1M0T1llUW5mVVhlZWFwM3F2ditvWC9XWHpWMXFXMGJESk4vejZxclo5WEYvcC9VdEE4Sm4vekUySnozClFiVkZEandWczU2N3VkTUxXd1p5dmxnd2RuL1BuUTQ2V3F5VU1kQlI0S0xzclVoSDhQV1dBdUFoSFN3R3JySnUKYWR6RWZFNTlQc0JrLzZ4MDdpQmMxMTNqK29RYXJ0b1dLM0lMOWNuRHFKUEJUQkxxeVVEaUlySW9rTTJRaS9TWQpyaGk1akRaTFVDSCtXRXFoeFJ3T0t4NkUzZ01EenRVanptSG5GMUZkUlVrRgotLS0tLUVORCBFTkNSWVBURUQgUFJJVkFURSBLRVktLS0tLQo",
                "password": "pass123word",
            }
        },
    ]
    put_tests = [
        {
            "name": "Check refid requirement",
            "status": 400,
            "return": 1009
        },
        {
            "name": "Check updating a non-existing certificate",
            "status": 400,
            "return": 1009,
            "req_data": {"refid": "INVALID"}
        },
        {
            "name": "Update an existing certificate",
            "req_data": {
                "descr": "E2E Test",
                "crt": CRT,
                "prv": PRV
            }
        },
        {
            "name": "Check update bad csr request with invalid cert",
            "status": 400,
            "return": 1049,
            "req_data_callable": "build_invalid_csr_request_cert"
        },
        {
            "name": "Check update bad csr request crt and prv do not match",
            "status": 400,
            "return": 1049,
            "req_data_callable": "build_invalid_csr_request_crt_prv_no_match"
        },
        {
            "name": "Check update bad csr request csr update with prv",
            "status": 400,
            "return": 1093,
            "req_data_callable": "build_invalid_csr_request_prv_not_allow_in_csr"
        },
        {
            "name": "Update a csr with certificate",
            "req_data_callable": "build_csr_cert_upload_request",
        },
        {
            "name": "Check update crt prv bad request with invalid cert",
            "status": 400,
            "return": 1003,
            "req_data_callable": "build_invalid_crt_prv_request_cert"
        },
        {
            "name": "Check update crt prv bad request encrypted prv",
            "status": 400,
            "return": 1036,
            "req_data_callable": "build_invalid_crt_prv_request_encrypted_prv"
        },
        {
            "name": "Check update crt prv bad request crt and prv do not match 1",
            "status": 400,
            "return": 1049,
            "req_data_callable": "build_invalid_crt_prv_request_crt_prv_no_match_1"
        },
        {
            "name": "Check update crt prv bad request crt and prv do not match 2",
            "status": 400,
            "return": 1049,
            "req_data_callable": "build_invalid_crt_prv_request_crt_prv_no_match_2"
        },
        {
            "name": "Check update crt prv bad request crt and prv do not match 3",
            "status": 400,
            "return": 1049,
            "req_data_callable": "build_invalid_crt_prv_request_crt_prv_no_match_3"
        }
    ]
    delete_tests = [
        {
            "name": "Delete certificate",
            "req_data": {"descr": "E2E Test"}
        },
        {
            "name": "Delete internal certificate",
            "req_data": {"descr": "INTERNAL_CERT_RSA"}
        },
        {
            "name": "Delete internal certificate",
            "req_data": {"descr": "INTERNAL_CSR_RSA"}
        },
        {
            "name": "Delete internal certificate",
            "req_data": {"descr": "SIGNING_CERT_RSA_NOPRV"}
        },
        {
            "name": "Delete internal certificate",
            "req_data": {"descr": "SIGNING_CERT_RSA_PRV"}
        },
        {
            "name": "Delete internal certificate: PCKS12 Import 1",
            "req_data": {"descr": "PCKS12 Import 1"}
        },
        {
            "name": "Delete internal certificate: Encrypted PEM Key Import 1",
            "req_data": {"descr": "Encrypted PEM Key Import 1"}
        },
        {
            "name": "Delete CA certificate",
            "uri": "/api/v1/system/ca",
            "req_data": {"descr": "INTERNAL_CA_RSA"}
        },
        {
            "name": "Delete CA certificate: my intermediate ca",
            "uri": "/api/v1/system/ca",
            "req_data": {"descr": "my intermediate ca"}
        },
        {
            "name": "Delete CA certificate: my root ca",
            "uri": "/api/v1/system/ca",
            "req_data": {"descr": "my root ca"}
        },
        {
            "name": "Check deleting non-existing certificate ID",
            "status": 400,
            "return": 1009,
            "req_data": {"id": "INVALID"}
        },
        {
            "name": "Check deleting non-existing certificate reference ID",
            "status": 400,
            "return": 1009,
            "req_data": {"refid": "INVALID"}
        },
        {
            "name": "Check deleting non-existing certificate description",
            "status": 400,
            "return": 1009,
            "req_data": {"descr": "INVALID"}
        },
        {
            "name": "Check deleting certificate in use",
            "status": 400,
            "return": 1005,
            "req_data": {"id": 0}
        }
    ]

    def post_post(self):
        # Check our first POST response for the created CA's refid
        if len(self.post_responses) == 1:
            # Variables
            self.caref = self.post_responses[0]["data"]["refid"]
            counter = 0
            # Loop through all tests and auto-add the caref ID to tests that do not have the no_caref key set
            for test in self.post_tests:
                if "req_data" in test and "no_caref" not in test:
                    self.post_tests[counter]["req_data"]["caref"] = self.post_responses[0]["data"]["refid"]
                counter = counter + 1
        # Add imported certificates refid to the update certificate req_data
        elif len(self.post_responses) == 2:
            self.put_tests[2]["req_data"]["refid"] = self.post_responses[1]["data"]["refid"]


APIE2ETestSystemCertificate()
