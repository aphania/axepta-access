<?php

class Axepta
{
    const PAYSSL = "https://paymentpage.axepta.bnpparibas/payssl.aspx";
    const DIRECT = "https://paymentpage.axepta.bnpparibas/direct.aspx";
	
    const DIRECT3D = "https://paymentpage.axepta.bnpparibas/direct3d.aspx";
    const CAPTURE = "https://paymentpage.axepta.bnpparibas/capture.aspx";
    const CREDIT = "https://paymentpage.axepta.bnpparibas/credit.aspx";
	
    const INSTALMENT = "INSTALMENT";
    



    /** @var ShaComposer */
    private $secretKey;
	
    /** @var ShaComposer */
    private $cryptKey;

    private $pspURL = self::PAYSSL;

    private $parameters = array();

	/** Axepta fields **/
    private $pspFields = array(
		'Debug',
		'PayID',
		'TransID',
		'MerchantID',
		'Amount',
		'Currency',
		'MAC',
		
		'RefNr',
		'Amount3D',
		'URLSuccess',
		'URLFailure',
		'URLNotify',
		'Response',
		'UserData',
		'Capture',
		'OrderDesc',
		'ReqID',
		'Plain',
		'Custom',
		'expirationTime',
		'AccVerify',
		'RTF',
		'ChDesc',
		
		'Len',
		'Data',
		
		'Template',
		'Language',
		'Background',
		'URLBack',
		'CCSelect',
		
		
		'MID',
		'mid',
		'refnr',
		'XID',
		'Status',
		'Description',
		'Code',
		'PCNr',
		'CCNr',
		'CCCVC',
		'CCBrand',
		'CCExpiry',
		'TermURL',
		'UserAgent',
		'HTTPAccept',
		'AboID',
		'ACSXID',
		'MaskedPan',
		'CAVV',
		'ECI',
		'DDD',
		'Type',
		'Plain',
		'Custom',
		'CustomField1','CustomField2','CustomField3','CustomField4','CustomField5','CustomField6','CustomField7',
		'CustomField8','CustomField9','CustomField10','CustomField11','CustomField12','CustomField13','CustomField14'
		
    );
	/** Axepta request hmac fields **/
    private $QHMACFields = array(
        'PayID', 'TransID', 'MerchantID', 'Amount','Currency'
    );
	/** Axepta response hmac fields **/
    private $RHMACFields = array(
        'PayID', 'TransID', 'MerchantID', 'Status','Code'
    );
	
	/** Axepta blowfish crypt fields **/
    private $BfishFields = array(
		'PayID','TransID','Amount','Currency','MAC',
		'RefNr','Amount3D','URLSuccess','URLFailure','URLNotify','Response','UserData','Capture','OrderDesc','ReqID',
		'Plain','Custom','expirationTime','AccVerify','RTF','ChDesc',
		'MID','XID','Status','Description','Code','PCNr','CCNr','CCCVC','CCBrand','CCExpiry','TermURL','UserAgent',
		'HTTPAccept','AboID','ACSXID','MaskedPan','CAVV','ECI','DDD','Type','Plain','Custom'
		// 'CustomField1','CustomField2','CustomField3','CustomField4','CustomField5','CustomField6','CustomField7',
		// 'CustomField8','CustomField9','CustomField10','CustomField11','CustomField12','CustomField13','CustomField14'
		);
	
	/** Axepta request required fields **/
    private $requiredFields = array(
        // 'MerchantID', 'TransID', 'Amount', 'Currency','URLSuccess','URLFailure','URLNotify','OrderDesc'
         'MerchantID', 'TransID', 'Amount', 'Currency','OrderDesc'
   );

    public $allowedlanguages = array(
        'nl', 'fr', 'de', 'it', 'es', 'cy', 'en'
    );
	

    public function __construct($secret)
    {
        $this->secretKey = $secret;				// HMAC key
    }
	
    public function setCryptKey($secret)
    {
        $this->cryptKey = $secret;				// blowfish crypt key
    }
	
	/** hack to retrieve response field **/
    public function setReponse($encrypt='encrypt')
    {
        $this->parameters['Response'] = $encrypt;
    }
	
	/** HMAC compute and store in MAC field**/
	public function shaCompose(array $parameters)
    {
        // compose SHA string
        $shaString = '';
        foreach($parameters as $key) {
			if(array_key_exists($key, $this->parameters) && !empty($this->parameters[$key])) {
				$value = $this->parameters[$key];
				$shaString .= $value;
			}
            $shaString .= (array_search($key, $parameters) != (count($parameters)-1)) ? '*' : '';
        }
 		$this->parameters['MAC'] = hash_hmac('sha256', $shaString, $this->secretKey);
        return $this->parameters['MAC'];
   }
	
    /** @return string */
    public function getShaSign()
    {
        $this->validate();
        return $this->shaCompose($this->QHMACFields);
    }
	
	public function BfishCompose(array $parameters)
    {
        // compose Blowfish hex string
        $blowfishString = '';
		
		foreach($parameters as $key) {
			if(array_key_exists($key, $this->parameters) && !empty($this->parameters[$key])) {
				$value = $this->parameters[$key];
				$blowfishString .= $key.'='.$value.'&';
			}
		}
		$blowfishString = rtrim($blowfishString,'&');
		$this->parameters['Debug'] = $blowfishString;
		$this->parameters['Len'] = strlen($blowfishString);
		$this->parameters[self::DATA_FIELD] = bin2hex($this->encrypt($blowfishString,$this->cryptKey));

		return $this->parameters[self::DATA_FIELD];
    }
	
    /** @return string */
    public function getBfishCrypt()
    {
        $this->validate();
        return $this->BFishCompose($this->BfishFields);
    }

	private function encrypt($data, $key)
    {
        $l = strlen($key);
        if ($l < 16)
            $key = str_repeat($key, ceil(16/$l));

        if ($m = strlen($data)%8)
            $data .= str_repeat("\x00",  8 - $m);
        if (function_exists('mcrypt_encrypt'))
            $val = mcrypt_encrypt(MCRYPT_BLOWFISH, $key, $data, MCRYPT_MODE_ECB);
        else
            $val = openssl_encrypt($data, 'BF-ECB', $key, OPENSSL_RAW_DATA | OPENSSL_NO_PADDING);

        return $val;
    }

    private function decrypt($data, $key)
    {
        $l = strlen($key);
        if ($l < 16)
            $key = str_repeat($key, ceil(16/$l));

        if (function_exists('mcrypt_encrypt'))
            $val = mcrypt_decrypt(MCRYPT_BLOWFISH, $key, $data, MCRYPT_MODE_ECB);
        else
            $val = openssl_decrypt($data, 'BF-ECB', $key, OPENSSL_RAW_DATA | OPENSSL_NO_PADDING);
        return rtrim($val, "\0");
    }
	
    /** @return string */
    public function getUrl()
    {
        return $this->pspURL;
    }

    public function setUrl($pspUrl)
    {
        $this->validateUri($pspUrl);
        $this->pspURL = $pspUrl;
    }

    public function setURLSuccess($url)
    {
        $this->validateUri($url);
        $this->parameters['URLSuccess'] = $url;
    }
	
    public function setURLFailure($url)
    {
        $this->validateUri($url);
        $this->parameters['URLFailure'] = $url;
    }

    public function setURLNotify($url)
    {
        $this->validateUri($url);
        $this->parameters['URLNotify'] = $url;
    }

    public function setTransID($transactionReference)
    {
        if(preg_match('/[^a-zA-Z0-9_-]/', $transactionReference)) {
            throw new \InvalidArgumentException("TransactionReference cannot contain special characters");
        }
        $this->parameters['TransID'] = $transactionReference;
    }

    /**
	 * Set amount in cents, eg EUR 12.34 is written as 1234
	 */
	public function setAmount($amount)
	{
		if(!is_int($amount)) {
			throw new InvalidArgumentException("Integer expected. Amount is always in cents");
		}
		if($amount <= 0) {
			throw new InvalidArgumentException("Amount must be a positive number");
		}
		$this->parameters['Amount'] = $amount;

	}

     
    public function setCaptureDay($number)
    {
        if (strlen($number) > 2) {
            throw new InvalidArgumentException("captureDay is too long");
        }
        $this->parameters['captureDay'] = $number;
    }
    
    // Methodes liees a la lutte contre la fraude
    
    public function setFraudDataBypass3DS($value)
    {
	if(strlen($value) > 128) {
            throw new InvalidArgumentException("fraudData.bypass3DS is too long");
        }
        $this->parameters['fraudData.bypass3DS'] = $value;
    }
    
    // Methodes liees au paiement one-click
    
    public function setMerchantWalletId($wallet)
    {
        if(strlen($wallet) > 21) {
            throw new InvalidArgumentException("merchantWalletId is too long");
        }
        $this->parameters['merchantWalletId'] = $wallet;
    }
    
    public function setPaymentPattern($paymentPattern)
    {
        $this->parameters['paymentPattern'] = $paymentPattern;
    }

    public function __call($method, $args)
    {
        if(substr($method, 0, 3) == 'set') {
            // $field = lcfirst(substr($method, 3));
			$field = substr($method, 3);
             if(in_array($field, $this->pspFields)) {
                $this->parameters[$field] = $args[0];
                return;
            }
        }

        if(substr($method, 0, 3) == 'get') {
 //           $field = lcfirst(substr($method, 3));
           $field = substr($method, 3);
           if(array_key_exists($field, $this->parameters)) {
                return $this->parameters[$field];
            }
        }

        throw new BadMethodCallException("Unknown method $method");
    }

    public function toArray()
    {
        return $this->parameters;
    }

    public function toParameterString()
    {
        $parameterString = "";
        foreach($this->parameters as $key => $value) {
            $parameterString .= $key . '=' . $value;
            $parameterString .= (array_search($key, array_keys($this->parameters)) != (count($this->parameters)-1)) ? '|' : '';
        }

        return $parameterString;
    }

    /** @return PaymentRequest */
    public static function createFromArray(ShaComposer $shaComposer, array $parameters)
    {
        $instance = new static($shaComposer);
        foreach($parameters as $key => $value)
        {
            $instance->{"set$key"}($value);
        }
        return $instance;
    }

    public function validate()
    {
        foreach($this->requiredFields as $field) {
            if(empty($this->parameters[$field])) {
                throw new \RuntimeException($field . " can not be empty");
            }
        }
    }

    protected function validateUri($uri)
    {
        if(!filter_var($uri, FILTER_VALIDATE_URL)) {
            throw new InvalidArgumentException("Uri is not valid");
        }
        if(strlen($uri) > 200) {
            throw new InvalidArgumentException("Uri is too long");
        }
    }
	
    // Traitement des reponses d'Axepta
    // -----------------------------------
	
	/** @var string */
    const SHASIGN_FIELD = "MAC";

    /** @var string */
    const DATA_FIELD = "Data";

    public function setResponse(array $httpRequest)
    {
        // use lowercase internally
        // $httpRequest = array_change_key_case($httpRequest, CASE_UPPER);

        // set sha sign        
        // $this->shaSign = $this->extractShaSign($httpRequest);

        // filter request for Sips parameters
        $this->parameters = $this->filterRequestParameters($httpRequest);
    }
	
    /**
     * @var string
     */
    private $shaSign;

    private $dataString;
	
    /**
     * Filter http request parameters
     * @param array $requestParameters
     */
    private function filterRequestParameters(array $httpRequest)
    {
        //filter request for Sips parameters
		$parameters = $this->parameters;
        if(!array_key_exists(self::DATA_FIELD, $httpRequest) || $httpRequest[self::DATA_FIELD] == '') {
            // throw new InvalidArgumentException('Data parameter not present in parameters.');
			$parameters['Debug'] = implode('&',$httpRequest);
			foreach($httpRequest as $key=>$value) {
				$key = ($key=='mid')? 'MerchantID':$key;
				$parameters[$key]=$value;
			}
		} else {
			$parameters[self::DATA_FIELD] = $httpRequest[self::DATA_FIELD];
			$this->dataString = $this->decrypt(hex2bin($parameters[self::DATA_FIELD]),$this->cryptKey);
			$parameters['Debug'] = $this->dataString;
			$dataParams = explode('&', $this->dataString);
			foreach($dataParams as $dataParamString) {
				$dataKeyValue = explode('=',$dataParamString,2);
				$key = ($dataKeyValue[0]=='mid')?'MerchantID':$dataKeyValue[0];
				$parameters[$key] = $dataKeyValue[1];
			}
			
		}

        return $parameters;
    }

    public function getSeal()
    {
        return $this->shaSign;
    }

    private function extractShaSign(array $parameters)
    {
        if(!array_key_exists(self::SHASIGN_FIELD, $parameters) || $parameters[self::SHASIGN_FIELD] == '') {
            throw new InvalidArgumentException('SHASIGN parameter not present in parameters.');
        }
        return $parameters[self::SHASIGN_FIELD];
    }

    /**
     * Checks if the response is valid
     * @param ShaComposer $shaComposer
     * @return bool
     */
    public function isValid()
    {
        // return $this->shaCompose($this->RHMACFields) == $this->shaSign;
        return $this->shaCompose($this->RHMACFields) == $this->parameters['MAC'];
    }

    /**
     * Retrieves a response parameter
     * @param string $param
     * @throws \InvalidArgumentException
     */
    public function getParam($key)
    {
        if(method_exists($this, 'get'.$key)) {
            return $this->{'get'.$key}();
        }

        // always use uppercase
        // $key = strtoupper($key);
        // $parameters = array_change_key_case($this->parameters,CASE_UPPER);
        $parameters = $this->parameters;
        if(!array_key_exists($key, $parameters)) {
            throw new InvalidArgumentException('Parameter ' . $key . ' does not exist.');
        }

        return $parameters[$key];
    }

    /**
     * @return int Amount in cents
     */
    public function getAmount()
    {
        $value = trim($this->parameters['Amount']);
        return (int) ($value);
    }

    public function isSuccessful()
    {
        return in_array($this->getParam('Status'), array("OK", "AUTHORIZED"));
    }

    public function getDataString()
    {
        return $this->dataString;
    }
}

?>
