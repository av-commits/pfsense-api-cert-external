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

class APISystemCertificateUpdate extends APIModel {

    # Create our method constructor
    public function __construct() {
        parent::__construct();
        $this->privileges = ["page-all", "page-system-certmanager"];
        $this->change_note = "Modified system certificate via API";
    }

    public function action() {
        # Update certificate
        $this->set_config("cert/{$this->id}", $this->validated_data);

        # If user requests this cert to be active, configure it as the wc cert
        $restart_webcfg = false;
        if ($this->initial_data["active"] === true and $this->validated_data["type"] === "server") {
            $this->set_config("system/webgui/ssl-certref", $this->validated_data["refid"]);
            $restart_webcfg = true;
        }

        # Write changes to configuration
        $this->write_config();

        # Restart our webgui if certificate has been activated
        if ($restart_webcfg === true) {
            APITools\restart_webconfigurator();
        }

        $res = $this->get_config("cert/{$this->id}");

        return APIResponse\get(0, $res);
    }

    public function validate_payload() {
        # do backwards compatible once
        # Convert 'cert' to 'crt' to remain backwards compatible
        if (isset($this->initial_data["cert"])) {
            $this->initial_data["crt"] = $this->initial_data["cert"];
        }
        # Convert 'key' to 'prv' to remain backwards compatible
        if (isset($this->initial_data["key"])) {
            $this->initial_data["prv"] = $this->initial_data["key"];
        }

        $this->__validate_refid();
        $this->__validate_crt_and_prv();
        $this->__validate_descr();
    }

    private function __validate_refid() {
        # Validate required 'refid' field containing the refid of an existing certificate. If refid is not passed, find the cert through 'descr' field
        if (isset($this->initial_data["refid"])) {
            # Loop through each cert and check for a match
            foreach ($this->get_config("cert", []) as $id=>$cert) {
                # Check if the field 'refid' matches the certificate's refid
                if ($this->initial_data["refid"] === $cert["refid"]) {
                    $this->id = $id;
                    $this->validated_data = $cert;
                    break;
                }
            }
        }
        # If we did not find an ID in the loop, return a not found error
        if (is_null($this->id)) {
            $this->errors[] = APIResponse\get(1009);
        }
    }

    private function __validate_crt_and_prv() {
        # combine the validation of optional crt and prv because many validation need both values
        if (isset($this->initial_data["crt"]) && isset($this->validated_data["csr"])) {
            # update csr use case if request contains crt and config csr
            if (isset($this->initial_data["prv"])) {
                $this->errors[] = APIResponse\get(1093);
            }
            $crt = base64_decode($this->initial_data["crt"]);
            $prv = base64_decode($this->validated_data["prv"]);

            if (cert_get_publickey($crt, false) != cert_get_publickey($prv, false, 'prv')) {
                $this->errors[] = APIResponse\get(1049);
            }

            csr_complete($this->validated_data, $crt);
        }
        elseif (isset($this->initial_data["crt"]) || isset($this->initial_data["prv"])) {
            $crt = base64_decode($this->initial_data["crt"]);
            $prv = base64_decode($this->initial_data["prv"]);
            if (empty($crt)) $crt = base64_decode($this->validated_data["crt"]);
            if (empty($prv)) $prv = base64_decode($this->validated_data["prv"]);

            if (!strstr($crt, "BEGIN CERTIFICATE") || !strstr($crt, "END CERTIFICATE")) {
                $this->errors[] = APIResponse\get(1003);
            }

            # Check if this private key is encrypted
            if (strstr($prv, "ENCRYPTED")) {
                $this->errors[] = APIResponse\get(1036);
            }

            if (cert_get_publickey($crt, false) != cert_get_publickey($prv, false, 'prv')) {
                $this->errors[] = APIResponse\get(1049);
            }

            cert_import($this->validated_data, $crt, $prv);
        }
    }

    private function __validate_descr() {
        # Validate the optional 'descr' field
        if (isset($this->initial_data['descr'])) {
            # Ensure description does not contain invalid characters
            if (preg_match("/[\?\>\<\&\/\\\"\']/", $this->initial_data['descr'])) {
                $this->errors[] = APIResponse\get(1037);
            } else {
                $this->validated_data["descr"] = $this->initial_data['descr'];
            }
        }
    }
}
