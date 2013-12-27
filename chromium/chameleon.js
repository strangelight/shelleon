
	/*
		* A JavaScript implementation of the Secure Hash Algorithm, SHA-1, as defined
		* in FIPS PUB 180-1
		* Version 2.1 Copyright Paul Johnston 2000 - 2002.
		* Other contributors: Greg Holt, Andrew Kepert, Ydnar, Lostinet
		* Distributed under the BSD License
		* See http://pajhome.org.uk/crypt/md5 for details.
		*/

    var secretpasswordtextbox = document.getElementById("secretpassword");

	var b64pad  = "";
	var chrsz   = 8;

	function generate(secretpassword, sitename) {
	    var pwd = "";
        var error = "";
	    if (sitename.length == 0)
	        error = error + " sitename";
	    if (secretpassword.length == 0)
	        error = error + " secretpassword";
	    
	    if (error.length == 0) {
	        var input = secretpassword + ':' + sitename.toLowerCase();
	        pwd = binb2b64(core_sha1(str2binb(input), input.length * chrsz));
	        pwd = pwd.substring(0, 10);
	        pwd = ensurenumberandletter(pwd);
	    }

	    return { password: pwd, error: error };
	}

	function core_sha1(x, len)
	{
		x[len >> 5] |= 0x80 << (24 - len % 32);
		x[((len + 64 >> 9) << 4) + 15] = len;

		var w = Array(80);
		var a =  1732584193;
		var b = -271733879;
		var c = -1732584194;
		var d =  271733878;
		var e = -1009589776;

		for(var i = 0; i < x.length; i += 16)
		{
		var olda = a;
		var oldb = b;
		var oldc = c;
		var oldd = d;
		var olde = e;

		for(var j = 0; j < 80; j++)
		{
			if(j < 16) w[j] = x[i + j];
			else w[j] = rol(w[j-3] ^ w[j-8] ^ w[j-14] ^ w[j-16], 1);
			var t = safe_add(safe_add(rol(a, 5), sha1_ft(j, b, c, d)),
			                safe_add(safe_add(e, w[j]), sha1_kt(j)));
			e = d;
			d = c;
			c = rol(b, 30);
			b = a;
			a = t;
		}

		a = safe_add(a, olda);
		b = safe_add(b, oldb);
		c = safe_add(c, oldc);
		d = safe_add(d, oldd);
		e = safe_add(e, olde);
		}
		return Array(a, b, c, d, e);

	}

	function sha1_ft(t, b, c, d)
	{
		if(t < 20) return (b & c) | ((~b) & d);
		if(t < 40) return b ^ c ^ d;
		if(t < 60) return (b & c) | (b & d) | (c & d);
		return b ^ c ^ d;
	}

	function sha1_kt(t)
	{
		return (t < 20) ?  1518500249 : (t < 40) ?  1859775393 :
			    (t < 60) ? -1894007588 : -899497514;
	}

	function safe_add(x, y)
	{
		var lsw = (x & 0xFFFF) + (y & 0xFFFF);
		var msw = (x >> 16) + (y >> 16) + (lsw >> 16);
		return (msw << 16) | (lsw & 0xFFFF);
	}

	function rol(num, cnt)
	{
		return (num << cnt) | (num >>> (32 - cnt));
	}

	function str2binb(str)
	{
		var bin = Array();
		var mask = (1 << chrsz) - 1;
		for(var i = 0; i < str.length * chrsz; i += chrsz)
		bin[i>>5] |= (str.charCodeAt(i / chrsz) & mask) << (24 - i%32);
		return bin;
	}

	function binb2b64(binarray)
	{
	    var tab = "ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz123456789?!#@&$";
		var str = "";
		for(var i = 0; i < binarray.length * 4; i += 3)
		{
		var triplet = (((binarray[i   >> 2] >> 8 * (3 -  i   %4)) & 0xFF) << 16)
			        | (((binarray[i+1 >> 2] >> 8 * (3 - (i+1)%4)) & 0xFF) << 8 )
			        |  ((binarray[i+2 >> 2] >> 8 * (3 - (i+2)%4)) & 0xFF);
		for(var j = 0; j < 4; j++)
		{
			if(i * 8 + j * 6 > binarray.length * 32) str += b64pad;
			else str += tab.charAt((triplet >> 6*(3-j)) & 0x3F);
		}
		}
		return str;
	}

	function ensurenumberandletter(s) { // dZ7LwMkdoQ
		var numbers = "123456789";
	    var letters = "ABCDEFGHIJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
	    var punct = "?!#@&$";
	    var hasnumber = 0;
	    var hasletter = 0;
	    var haspunct = 0;

	    for (var i = 0; i < s.length; i++) {
	        if (numbers.indexOf(s[i]) > -1)
	            hasnumber = 1;
	        if (letters.indexOf(s[i]) > -1)
	            hasletter = 1;
	        if (punct.indexOf(s[i]) > -1)
	            haspunct = 1;
	    }
	    if (hasnumber == 0){
	        s = "1" + s.substring(1); 
			return ensurenumberandletter(s);
		}
		if (hasletter == 0){
	        s = s.substring(0, 1) + "a" + s.substring(2);
			return ensurenumberandletter(s);
		}
	    if (haspunct == 0){
	        s = s.substring(0, 2) + "@" + s.substring(3);
			return ensurenumberandletter(s);
		}
	    return s;
	}
	function shortenurl(url) {
	    // remove protocol (http://, ftp://, etc)
	    if (url.indexOf("//") > -1)
	        url = url.substring(url.indexOf("//") + 2);
	    // remove port (:8080, etc)
	    if (url.indexOf(':') > 1)
	        url = url.split(':')[0];
	    // remove domain-specific parts (/index.html, etc)
	    if (url.indexOf('/') > -1)
	        url = url.split('/')[0];
	    // remove queries (google.com?q=hello)
	    if (url.indexOf('?') > -1)
	        url = url.split('?')[0];

	    // split into parts.
	    var urlParts = url.split('.');
	    // remove all parts until either there are only 2 parts left
	    // or there is only one long part left
	    while (urlParts.length > 1 && urlParts[1].length > 3)
	        urlParts.splice(0,1);
	    return urlParts.join('.');


	    return url;
	}

	function handlegeneratebuttonclicked() {
        
        var sitenametextbox = document.getElementById("sitename1");
        var passwordtextbox = document.getElementById("password");
	    var result = generate(secretpasswordtextbox.value, sitenametextbox.value);

	    if (result.error.indexOf('sitename') == -1) {
	        document.getElementById('sitenameerror').setAttribute('class', 'clearfix');
	    }
	    else {
	        document.getElementById('sitenameerror').setAttribute('class', 'clearfix error');
	        sitenametextbox.focus();
	    }
	    sitenametextbox.value = sitenametextbox.value.toLowerCase();

	    if (result.error.indexOf('secretpassword') == -1) {
	        document.getElementById('secretpassworderror').setAttribute('class', 'clearfix');
	    }
	    else {
	        document.getElementById('secretpassworderror').setAttribute('class', 'clearfix error');
	        secretpasswordtextbox.focus();
	    }

	    if (result.error.length == 0) {
	        passwordtextbox.value = result.password;
	        document.getElementById('sitename2').innerHTML = sitenametextbox.value;
	        document.getElementById('passwordmessage').style.display = 'block';
	        passwordtextbox.focus();
	        passwordtextbox.select();
	        document.execCommand('copy');
	    }
	    else {
	        passwordtextbox.value = '';
	        document.getElementById('sitename2').innerHTML = '';
	        document.getElementById('passwordmessage').style.display = 'none';
	    }
	}

	function setsitename(tablink) {
	    var sitenametextbox = document.getElementById("sitename1");
	    sitenametextbox.value = shortenurl(tablink);
	}

	var generateButton = document.getElementById("generatebutton");
	generateButton.addEventListener("click", handlegeneratebuttonclicked, false);

	chrome.tabs.query({ active: true, currentWindow: true }, function (tabs) { setsitename(tabs[0].url); });
	secretpasswordtextbox.focus();
	