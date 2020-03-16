# axepta-access *request builder / response identify  &amp; decode*
## Request page

	### Init the class

			$paymentRequest = new Axepta($Your_HMAC);
			$paymentRequest->setCryptKey($Your_CRYPTKEY);
			
	### Set your data in

			$paymentRequest->setUrl(Axepta::PAYSSL);
			$paymentRequest->setMerchantID($Your_MERCHANTID);
			$paymentRequest->setTransID("AssociationMR" . $Your_Payment_id."/".rand(100000,999999));
			$paymentRequest->setAmount($Your_Amount*100);
			$paymentRequest->setCurrency('EUR');
			$paymentRequest->setRefNr($Your_Ref);
			
			$paymentRequest->setURLSuccess("Your success URL page");    
			$paymentRequest->setURLFailure("Your failure URL page");    
			$paymentRequest->setURLNotify("Your notify URL page"); 
			
			$paymentRequest->setURLBack("Your cancel URL back page");    
			$paymentRequest->setReponse('encrypt');    
			$paymentRequest->setLanguage('fr');
			$paymentRequest->setOrderDesc('Your Order description text');
			// ...
			
			// check your data
			$paymentRequest->validate();
		
			// compute
			$mac = $paymentRequest->getShaSign() ; 		// run HMAC hash
			$data = $paymentRequest->getBfishCrypt();	// run Crypt & retrieve Data
			$len = $paymentRequest->getLen();			// retrieve Crypt length

	### Fill your form

		   echo "<html><body><form name=\"redirectForm\" method=\"GET\" action=\"" . $paymentRequest->getUrl() . "\">" .
				 "<input type=\"hidden\" name=\"MerchantID\" value=\"". $paymentRequest->getMerchantID() . "\">" .
				 "<input type=\"hidden\" name=\"Len\" value=\"". $paymentRequest->getLen() . "\">" .
				 "<input type=\"hidden\" name=\"Data\" value=\"". $paymentRequest->getBfishCrypt() . "\">" .
				 "<input type=\"hidden\" name=\"URLBack\" value=\"". $paymentRequest->getURLBack() . "\">" .
				 "<input type=\"hidden\" name=\"CustomField1\" value=\"". $paymentRequest->getAmount()/100 . "\">" .
				 "<input type=\"hidden\" name=\"CustomField2\" value=\"". $paymentRequest->getTransID() . "\">" .
				 "<input type=\"hidden\" name=\"CustomField3\" value=\"". $Your_logo_img . "\">" .
				 "<input type=\"hidden\" name=\"CustomField8\" value=\"". $Your_miscelaneous text . "\">" .
				 "<noscript><input type=\"submit\" name=\"Go\" value=\"Click to continue\"/></noscript> </form>" .
				 "<script type=\"text/javascript\">document.redirectForm.submit(); </script>" .
				 "</body></html>";

## Response page

	### Get the request response && check 

		$paymentResponse = new Axepta($Your_HMAC);
		$paymentResponse->setCryptKey($Your_CRYPTKEY);
		$paymentResponse->setResponse($_GET);
		if($paymentResponse->isValid() && $paymentResponse->isSuccessful()) { 
			$TransID = $paymentResponse->getPayID();
			$PCNr = $paymentResponse->getPCNr();
			$CCBrand  = $paymentResponse->getCCBrand();
			$CCExpiry = $paymentResponse->getCCExpiry();
			// .....
		} else {
			// Fail ....
		}
