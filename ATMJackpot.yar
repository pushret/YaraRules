rule ATMJackpot {
        meta:
                description = "Detects ATMJackpot malware"
                author = "PushRet(@ximerus)"
                reference = "Detects the ATMJackpot malware"
                date = "2018-07-24"
               	hash = "19ed96914796770c7b86eaab0370c0e8"
        strings:

                // DLL PROCEDURES ASSOCIATED WITH CUTLET ATM
                $dll_proc1 = "CscCngClose" wide ascii
                $dll_proc2 = "CscCngTransport" wide ascii
                $dll_proc3 = "CscCngReset" wide ascii
                $dll_proc4 = "CscCngDispense" wide ascii
                $dll_proc5 = "CscCngOpen" wide ascii
		$dll_proc6 = "CscCngStatusRead" wide ascii

                // CUTLET MALWARE STRINGS
                $str0 = "CSCCNG" wide ascii
		$str1 = "CSCWCNG" wide ascii
		$str2 = "Getting %d note(s) from %d"

        condition:
                4 of ($dll_proc*) and all of($str*)
}
