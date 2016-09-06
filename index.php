<?php
	if(!empty($_POST['str']) && !empty($_POST['key']))
	{
		$encrypted = RSA_Public_Encrypt($_POST['str'], $_POST['key']);
	}
	if(!empty($_POST['_str']) && !empty($_POST['_key']))
	{
		$decrypt = RSA_Private_Decrypt($_POST['_str'], $_POST['_key']);
	}
	if(!empty($_POST['str1']) && !empty($_POST['key1']))
	{
		$_encrypted = RSA_Private_Encrypt($_POST['str1'], $_POST['key1']);
	}
	if(!empty($_POST['_str1']) && !empty($_POST['_key1']))
	{
		$_decrypt = RSA_Public_Decrypt($_POST['_str1'], $_POST['_key1']);
	}
	
	if(!empty($_POST['data']) && !empty($_POST['prikey']))
	{
		openssl_sign(base64_decode($_POST['data']), $signature, $_POST['prikey'], "md5WithRSAEncryption");
		$signature = base64_encode($signature);
	}
	
	if(!empty($_POST['_data']) && !empty($_POST['url']))
	{
		$_data = trim($_POST['_data']);
		$result = RSA_Random($_data);
		$public_key = $result['public_key'];
		$private_key = $result['private_key'];
		$_signature = $result['signature'];
		$public_key = str_replace("-----BEGIN PUBLIC KEY-----", "", $public_key);
		$public_key = str_replace("-----END PUBLIC KEY-----", "", $public_key);
		$public_key = implode("", explode("\n", $public_key));
		// 私钥加密过的源数据，用于HTTP请求
		$_data = $result['data'];
		$headers = array(
	        'X-AjaxPro-Method:ShowList',
	        'Content-Type: application/json; charset=utf-8',
	        'Content-Length: ' . strlen($_signature),
	        'p: '.$_data,
	        'y: '.$public_key,
	    );
		$curl = request_by_curl($headers, $_signature, $_POST['url']);
		if ($curl['http_code'] == 200)
		{
			$curl_result = RSA_Private_Decrypt($curl['data'], $private_key);
		}
		else
		{
			$curl_result = $curl;
		}
	}
	
	if(!empty($_POST['sign']) && !empty($_POST['odata']) && !empty($_POST['pubkey']))
	{
		if (openssl_verify(base64_decode(trim($_POST['odata'])), base64_decode(trim($_POST['sign'])), trim($_POST['pubkey']), OPENSSL_ALGO_MD5) == 1)
		{
			$check_sign = 'success';
		}
		else
		{
			$check_sign = 'error';
		}
	}
	
	// curl请求
	function request_by_curl($headers, $data, $url)
	{
		try {
			$ch = curl_init();
			curl_setopt($ch, CURLOPT_URL, $url);
			curl_setopt($ch, CURLOPT_RETURNTRANSFER, 1);
			curl_setopt($ch, CURLOPT_HTTPHEADER, $headers);
			curl_setopt($ch, CURLOPT_POST, 1);
			curl_setopt($ch, CURLOPT_POSTFIELDS, $data);
			$data = curl_exec($ch);
			$http_code = curl_getinfo($ch, CURLINFO_HTTP_CODE);
			curl_close($ch);
			return array('data' => $data, 'http_code' => $http_code);
		} catch (Exception $e) {
			exit($e->getMessage());
		}
		
	}
	
	//公钥加密
	function RSA_Public_Encrypt($content, $key)
	{
		$public_key = trim($key);
		$res = openssl_get_publickey($public_key);
		$content = trim($content);
		$j=0;
		$x = strlen($content)/10;
		$y = floor($x);
		$crt = '';
		for($i=0; $i<$y; $i++)
		{
			$crypttext = '';
			openssl_public_encrypt(substr($content, $j, 10), $crypttext, $res);
			$j = $j+10;
			$crt .= $crypttext;
		}
		if((strlen($content)%10) > 0)
		{
			openssl_public_encrypt(substr($content, $j), $crypttext, $res);
			$crt .= $crypttext;
		}
		return base64_encode($crt);
	}
	
	//私钥加密
	function RSA_Private_Encrypt($content, $key)
	{
		$public_key = trim($key);
		$res = openssl_get_privatekey($public_key);
		$content = trim($content);
		$j=0;
		$x = strlen($content)/10;
		$y = floor($x);
		$crt = '';
		for($i=0; $i<$y; $i++)
		{
			$crypttext = '';
			openssl_private_encrypt(substr($content, $j, 10), $crypttext, $res);
			$j = $j+10;
			$crt .= $crypttext;
		}
		if((strlen($content)%10) > 0)
		{
			openssl_private_encrypt(substr($content, $j), $crypttext, $res);
			$crt .= $crypttext;
		}
		return base64_encode($crt);
	}
	
	
	//私钥解密
	function RSA_Private_Decrypt($content, $private_key, $bit=64)
	{
		$res = openssl_get_privatekey($private_key);
		//用base64将内容还原成二进制
		$content = base64_decode($content);
		//把需要解密的内容，按位数拆开解密
		$result = '';
		for($i = 0; $i < strlen($content)/$bit; $i++  )
		{
			$decrypt = '';
			$data = substr($content, $i * $bit, $bit);
			openssl_private_decrypt($data, $decrypt, $res);
			$result .= $decrypt;
		}
		openssl_free_key($res);
		return $result;
	}
	
	//公钥解密
	function RSA_Public_Decrypt($content, $public_key, $bit=64)
	{
		$res = openssl_get_publickey($public_key);
		//用base64将内容还原成二进制
		$content = base64_decode($content);
		//把需要解密的内容，按位数拆开解密
		$result = '';
		for ($i = 0; $i < strlen($content)/$bit; $i++)
		{
			$data = substr($content, $i * $bit, $bit);
			openssl_public_decrypt($data, $decrypt, $res);
			$result .= $decrypt;
		}
		openssl_free_key($res);
		return $result;
	}
	
	//随机生成RSA公私钥和签名
	function RSA_Random($data, $bit=512, $type='md5WithRSAEncryption')
	{
		$private_key_res = openssl_pkey_new(array(
			"private_key_bits" => $bit,
			"private_key_type" => OPENSSL_KEYTYPE_RSA,
		));
		openssl_pkey_export($private_key_res, $private_key);
		$details = openssl_pkey_get_details($private_key_res);
		
		$data = RSA_Private_Encrypt($data, $private_key);
		//create signature
		openssl_sign(base64_decode($data), $signature, $private_key, $type);
		return array('public_key' => $details['key'], 'private_key' => $private_key, 'signature' => base64_encode($signature), 'data' => $data);
	}
?>
<!DOCTYPE html>
<html>
  <head>
    <title>Tools</title>
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <!-- Bootstrap -->
    <link rel="stylesheet" href="http://cdn.bootcss.com/bootstrap/2.3.2/css/bootstrap.min.css">
    <style type="text/css">
	    pre {
	   	padding: 5px;
	    color: #009a61;
	    background-color: #f7f7f9;
	    border: 1px solid #e1e1e8;
	    }
    </style>
  </head>
  <body>
    <div class="container">
	<div class="page-header">
	  <h2>RSA Tools</h2>
	</div>
	<div class="tabbable" style="margin-bottom: 18px;">
	  <ul class="nav nav-tabs">
		<li class="<?php if ((isset($_GET['tab']) && $_GET['tab'] == 1) || empty($_GET['tab'])) echo "active";?>"><a href="#tab1" data-toggle="tab">公加私解</a></li>
		<li class="<?php if (isset($_GET['tab']) && $_GET['tab'] == 2) echo "active";?>"><a href="#tab2" data-toggle="tab">私加公解</a></li>
		<li class="<?php if (isset($_GET['tab']) && $_GET['tab'] == 3) echo "active";?>"><a href="#tab3" data-toggle="tab">签名验签</a></li>
		<li class="<?php if (isset($_GET['tab']) && $_GET['tab'] == 4) echo "active";?>"><a href="#tab4" data-toggle="tab">模拟请求</a></li>
	  </ul>
	  <div class="tab-content">
	  
		<div class="tab-pane <?php if ((isset($_GET['tab']) && $_GET['tab'] == 1) || empty($_GET['tab'])) echo "active";?>" id="tab1">
			<form method="post" action="?tab=1">
			<legend>RSA公钥加密</legend>
				<textarea name="key" rows="5" style="width: 920px;" placeholder="请输入公钥"><?php echo empty($_POST['key']) ? '' : $_POST['key'];?></textarea>
				<textarea name="str" rows="5" style="width: 920px;" placeholder="请输入加密明文"><?php echo empty($_POST['str']) ? '' : $_POST['str'];?></textarea>
				<button class="button" type="submit">加密</button>
			</form>
			<?php if (!empty($encrypted)):?>
			<input type="text" id="encrypted" value="<?php echo $encrypted;?>" style="width: 920px;" />
			<?php endif;?>
			<form method="post" action="?tab=1">
			<legend>RSA私钥解密</legend>
			<textarea name="_key" rows="10" style="width: 920px;" placeholder="请输入私钥"><?php echo empty($_POST['_key']) ? '' : $_POST['_key'];?></textarea>
			<textarea name="_str" rows="5" style="width: 920px;" placeholder="请输入密文"><?php echo empty($_POST['_str']) ? '' : $_POST['_str'];?></textarea>
			<button class="button" type="submit">解密</button>
			</form>
			<?php if (!empty($decrypt)):?>
			<code><?php echo $decrypt;?></code>
			<?php endif;?>
		</div>
		
		<div class="tab-pane <?php if ((isset($_GET['tab']) && $_GET['tab'] == 2)) echo "active";?>" id="tab2">
			<form method="post" action="?tab=2">
			<legend>RSA私钥加密</legend>
				<textarea name="key1" rows="10" style="width: 920px;" placeholder="请输入私钥"><?php echo empty($_POST['key1']) ? '' : $_POST['key1'];?></textarea>
				<textarea name="str1" rows="5" style="width: 920px;" placeholder="请输入加密明文"><?php echo empty($_POST['str1']) ? '' : $_POST['str1'];?></textarea>
				<button class="button" type="submit">加密</button>
			</form>
			<?php if (!empty($_encrypted)):?>
			<input type="text" id="_encrypted" value="<?php echo $_encrypted;?>" style="width: 920px;" />
			<?php endif;?>
			<form method="post" action="?tab=2">
				<textarea name="_key1" rows="5" style="width: 920px;" placeholder="请输入公钥"><?php echo empty($_POST['_key1']) ? '' : $_POST['_key1'];?></textarea>
				<textarea name="_str1" rows="9" style="width: 920px;" placeholder="请输入密文"><?php echo empty($_POST['_str1']) ? '' : $_POST['_str1'];?></textarea>
				<button class="button" type="submit">解密</button>
			</form>
			<?php if (!empty($_decrypt)):?>
			<code><?php echo $_decrypt;?></code>
			<?php endif;?>
		</div>
		
		
		<div class="tab-pane <?php if ((isset($_GET['tab']) && $_GET['tab'] == 3)) echo "active";?>" id="tab3">
			<form method="post" action="?tab=3">
			<legend>RSA签名</legend>
				<textarea name="data" rows="9" style="width: 920px;" placeholder="请输入源数据"><?php echo empty($_POST['data']) ? '' : $_POST['data'];?></textarea>
				<textarea name="prikey" rows="9" style="width: 920px;" placeholder="请输入私钥"><?php echo empty($_POST['prikey']) ? '' : $_POST['prikey'];?></textarea>
				<button class="button" type="submit">生成</button>
			</form>
			<?php if (!empty($signature)):?>
			<input type="text" id="signature" value="<?php echo $signature;?>" style="width: 920px;" />
			<?php endif;?>
			
			<form method="post" action="?tab=3">
			<legend>RSA验签</legend>
				<input type="text" name="sign" value="<?php echo empty($_POST['sign']) ? '' : $_POST['sign'];?>" placeholder="请输入签名" style="width: 920px;" />
				<textarea name="odata" rows="9" style="width: 920px;" placeholder="请输入源数据"><?php echo empty($_POST['odata']) ? '' : $_POST['odata'];?></textarea>
				<textarea name="pubkey" rows="9" style="width: 920px;" placeholder="请输入公钥"><?php echo empty($_POST['pubkey']) ? '' : $_POST['pubkey'];?></textarea>
				<button class="button" type="submit">校检</button>
			</form>
			<?php if (!empty($check_sign)):?>
			<?php if ($check_sign == 'success'):?>
			<div class="alert alert-success">校检成功</div>
			<?php else:?>
			<div class="alert alert-error">校检失败</div>
			<?php endif;?>
			<?php endif;?>
			
		</div>
		
		
		<div class="tab-pane <?php if ((isset($_GET['tab']) && $_GET['tab'] == 4)) echo "active";?>" id="tab4">
		  <form method="post" action="?tab=4">
		  <legend>模拟HTTP请求数据(RSA)</legend>
		  		<input type="text" name="url" placeholder="请输入请求URL" style="width: 920px;" value="<?php echo empty($_POST['url']) ? '' : $_POST['url'];?>" />
				<textarea name="_data" rows="9" style="width: 920px;" placeholder="请输入源数据（JSON数据流）"><?php echo empty($_POST['_data']) ? '' : $_POST['_data'];?></textarea>
				<button class="button" type="submit">请求</button>
				<p>
				<?php if (!empty($curl_result)):?>
				<?php echo "<pre>" .htmlspecialchars(print_r($curl_result, true)) ."</pre>";?>
				<?php if (!isset($curl_result['http_code'])){echo "<pre>" . htmlspecialchars(print_r(json_decode($curl_result, true), true)) ."</pre>";}?>
				<?php endif;?>
				</p>
			</form>
			<?php if (!empty($_data)):?>
			<label>私钥密文（Headers请求p参数）</label>
			<input type="text" value="<?php echo $_data;?>" style="width: 920px;" />
			<?php endif;?>
			<?php if (!empty($public_key)):?>
			<label>公钥（Header请求y参数）</label>
			<textarea name="_data" rows="5" style="width: 920px;"><?php echo $public_key;?></textarea>
			<?php endif;?>
			<?php if (!empty($_signature)):?>
			<label>签名（Body数据流）</label>
			<input type="text" value="<?php echo $_signature;?>" style="width: 920px;" />
			<?php endif;?>
			<?php if (!empty($private_key)):?>
			<label>私钥</label>
			<textarea name="_data" rows="10" style="width: 920px;"><?php echo $private_key;?></textarea>
			<?php endif;?>
		</div>
	  </div>
	</div>
	
	
	
	
	</div>
    <!-- jQuery文件。务必在bootstrap.min.js 之前引入 -->
	<script src="http://cdn.bootcss.com/jquery/1.11.1/jquery.min.js"></script>

	<!-- 最新的 Bootstrap 核心 JavaScript 文件 -->
	<script src="http://cdn.bootcss.com/bootstrap/2.3.2/js/bootstrap.min.js"></script>
	<script>
	$("#encrypted").focus();
	$("#encrypted").select();
	$("#_encrypted").focus();
	$("#_encrypted").select();
	$("#signature").focus();
	$("#signature").select();
	</script>
  </body>
</html>