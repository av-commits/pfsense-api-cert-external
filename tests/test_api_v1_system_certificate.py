"""Script used to test the /api/v1/system/certificate endpoint."""
import e2e_test_framework
import json
import base64
import pytz
from datetime import datetime, timedelta
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization

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
                    raise AssertionError(f"expect 'certtype' in 'intcsrrsa' certificate: 'certificate-referenced-ca', current: '{cert['certtype']}'")
                if not cert["csr"].startswith('LS0tLS1C'):
                    raise AssertionError(f"expect 'csr' in 'intcsrrsa' certificate: start with 'LS0tLS1C', current: '{cert['csr']}'")
                if not cert["keyavailable"]:
                    raise AssertionError(f"expect 'keyavailable' in 'intcsrrsa' certificate: 'True', current: '{cert['keyavailable']}'")
                if cert["subject"] != 'ST=Utah, OU=IT, O=Test Company, L=Salt Lake City, CN=internal-csr-e2e-test.example.com, C=US':
                    raise AssertionError(f"expect 'subject' in 'intcsrrsa' certificate: 'ST=Utah, OU=IT, O=Test Company, L=Salt Lake City, CN=internal-csr-e2e-test.example.com, C=US' current: '{cert['caref']}'")

        for key in cert_ass_done:
            if not cert_ass_done[key]:
                raise AssertionError(f"no certificate found for '{key}'")



    get_tests = [{"name": "Read system certificates",
        "post_test_callable":"get_certificate_assertions"}]
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
        }
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
            "name": "Delete CA certificate",
            "uri": "/api/v1/system/ca",
            "req_data": {"descr": "INTERNAL_CA_RSA"}
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
