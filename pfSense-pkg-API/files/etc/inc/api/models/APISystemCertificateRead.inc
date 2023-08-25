<?php
//   Copyright 2023 Jared Hendrickson
//
//   Licensed under the Apache License, Version 2.0 (the "License");
//   you may not use this file except in compliance with the License.
//   You may obtain a copy of the License at
//
//       http://www.apache.org/licenses/LICENSE-2.0
//
//   Unless required by applicable law or agreed to in writing, software
//   distributed under the License is distributed on an "AS IS" BASIS,
//   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
//   See the License for the specific language governing permissions and
//   limitations under the License.

require_once("api/framework/APIModel.inc");
require_once("api/framework/APIResponse.inc");


class APISystemCertificateRead extends APIModel {
    # Create our method constructor
    public function __construct() {
        parent::__construct();
        $this->privileges = ["page-all", "page-system-certmanager"];
    }

    public function action() {
        $removeKey = true;

        $data = $this->get_config("cert", []);
        foreach ($data as &$cert) {
            $cert["keyavailable"] = !empty($cert["prv"]);

            if (!empty($cert["crt"])) {
                $cert["subject"] = cert_get_subject($cert['crt']);
                $cert["issuer"] = cert_get_issuer($cert['crt']);

                if ($cert["subject"] == $cert["issuer"] && $cert["subject"] != "unknown")
                    $cert["certtype"] = "self-signed";
                elseif (!empty($cert["caref"]))
                    $cert["certtype"] = "certificate-referenced-ca";
                else
                    $cert["certtype"] = "certificate";

                $purpose = cert_get_purpose($cert['crt']);
                $cert["iscacert"] = ($purpose['ca'] == 'Yes');
                $cert["isservercert"] = ($purpose['server'] == 'Yes');

                $cert["isrevoked"] = is_cert_revoked($cert);

                if (is_webgui_cert($cert['refid'])) $cert["inuse"][] = "webConfigurator";
                if (is_user_cert($cert['refid'])) $cert["inuse"][] = "User Cert";
                if (is_openvpn_server_cert($cert['refid'])) $cert["inuse"][] = "OpenVPN Server";
                if (is_openvpn_client_cert($cert['refid'])) $cert["inuse"][] = "OpenVPN Client";
                if (is_ipsec_cert($cert['refid'])) $cert["inuse"][] = "IPsec Tunnel";
                if (is_captiveportal_cert($cert['refid'])) $cert["inuse"][] = "Captive Portal";
                if (is_unbound_cert($cert['refid'])) $cert["inuse"][] = "DNS Resolver";
                //TODO inuse by package cert_usedby_description

                $str_crt = base64_decode($cert["crt"]);
                $cert_details = openssl_x509_parse($str_crt);

                $validFrom = cert_format_date($cert_details['validFrom'], $cert_details['validFrom_time_t'], false);
                if ($validFrom instanceof DateTime) $cert["validfrom"] = $validFrom->format("c");
                $validTo = cert_format_date($cert_details['validTo'], $cert_details['validTo_time_t'], false);
                if ($validTo instanceof DateTime) $cert["validto"] = $validTo->format("c");

                if (isset($cert_details['serialNumber']) && (strlen($cert_details['serialNumber']) > 0))
                    $cert["serial"] = $cert_details['serialNumber'];

                $certsig = cert_get_sigtype($cert['crt']);
                if (is_array($certsig) && !empty($certsig) && !empty($certsig['shortname']))
                    $cert["sigtype"] = $certsig['shortname'];

                $sans = cert_get_sans($cert['crt']);
                if (is_array($sans) && !empty($sans)) {
                    $cert["altnames"] = array();
                    foreach ($sans as $san) {
                        $san_arr = explode(':', $san, 2);

                        $alt_types = array("dns", "ip", "uri", "email");
                        foreach ($alt_types as $at) {
                            if (substr(strtolower(trim($san_arr[0])), 0, strlen($at)) === $at) {
                                $san_obj[$at] = trim($san_arr[1]);
                                $cert["altnames"][] = $san_obj;
                                unset($san_obj);
                            }
                        }
                    }
                }

                $purpose = cert_get_purpose($cert['crt']);
                if (is_array($purpose) && !empty($purpose['ku']))
                    $cert["keyusage"] = $purpose['ku'];

                if (is_array($purpose) && !empty($purpose['eku']))
                    $cert["extendedkeyusage"] = $purpose['eku'];

                if (cert_get_ocspstaple($cert['crt']))
                    $cert["ocspmuststaple"] = true;

                if (!empty($cert_details['hash']))
                    $cert["hash"] = $cert_details['hash'];

                if (is_array($cert_details["extensions"]) && !empty($cert_details["extensions"]["subjectKeyIdentifier"]))
                    $cert["subjectkeyid"] = $cert_details["extensions"]["subjectKeyIdentifier"];

                if (is_array($cert_details["extensions"]) && !empty($cert_details["extensions"]["authorityKeyIdentifier"]))
                    $cert["authoritykeyid"] = $cert_details["extensions"]["authorityKeyIdentifier"];

                $lifetime = cert_get_lifetime($cert);
                $expiredays = cert_get_lifetime($cert, true);
                if ($lifetime !== false) {
                    $cert["totallifetime"] = $lifetime;
                    $cert["lifetimeremaining"] = $expiredays;
                }
            } elseif (!empty($cert["csr"])) {
                $cert["certtype"] = "certificate-signing-request";
                $cert["subject"] = csr_get_subject($cert['csr']);
            } elseif (!empty($cert["prv"])) {
                $cert["certtype"] = "private-key-only";
            } else
                $cert["certtype"] = "unknown";

            if (!empty($cert["prv"])) {
                $res_key = openssl_pkey_get_private(base64_decode($cert['prv']));
                if ($res_key) {
                    $key_details = openssl_pkey_get_details($res_key);
                    if ($key_details['type'] == OPENSSL_KEYTYPE_RSA) {
                        $cert["keytype"] = 'RSA';
                        $cert["keylen"] = $key_details['bits'];
                    } else {
                        $cert["keytype"] = "ECDSA";
                        $curve = cert_get_pkey_curve($cert['prv']);

                        if (!empty($curve))
                            $cert["ecname"] = "$curve";
                    }
                }
            }

            if ($removeKey && isset($cert["prv"]))
                unset($cert["prv"]);

        }

        return APIResponse\get(0, $data);
    }
}
