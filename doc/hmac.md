

#Module hmac#
* [Description](#description)
* [Function Index](#index)
* [Function Details](#functions)


HMAC wrappers for erlsha2.

__Authors:__ Jared Flatow, Steve Vinoski.

__References__* Based on the
[
mailing list response
](http://erlang.org/pipermail/erlang-questions/2011-May/058174.md)
by Steve Davis.
<a name="index"></a>

##Function Index##


<table width="100%" border="1" cellspacing="0" cellpadding="2" summary="function index"><tr><td valign="top"><a href="#hexlify-1">hexlify/1</a></td><td>Convert binary to equivalent hexadecimal string.</td></tr><tr><td valign="top"><a href="#hmac-2">hmac/2</a></td><td>Compute a SHA MAC message authentication code from key and data.</td></tr><tr><td valign="top"><a href="#hmac-4">hmac/4</a></td><td>Compute a SHA MAC message authentication code from key and data using
the specified hash function and blocksize.</td></tr><tr><td valign="top"><a href="#hmac224-2">hmac224/2</a></td><td>Compute a SHA-224 MAC message authentication code from key and data.</td></tr><tr><td valign="top"><a href="#hmac256-2">hmac256/2</a></td><td>Compute a SHA-256 MAC message authentication code from key and data.</td></tr><tr><td valign="top"><a href="#hmac384-2">hmac384/2</a></td><td>Compute a SHA-384 MAC message authentication code from key and data.</td></tr><tr><td valign="top"><a href="#hmac512-2">hmac512/2</a></td><td>Compute a SHA-512 MAC message authentication code from key and data.</td></tr></table>


<a name="functions"></a>

##Function Details##

<a name="hexlify-1"></a>

###hexlify/1##


<pre>hexlify(Binary :: binary()) -&gt; list()</pre>

Convert binary to equivalent hexadecimal string.
<a name="hmac-2"></a>

###hmac/2##


<pre>hmac(Key :: <a href="#type-key">key()</a>, Data :: <a href="#type-data">data()</a>) -> <a href="#type-mac">mac()</a></pre>
<ul class="definitions"><li><pre>&lt;a name="type-key"&gt;key()&lt;/a&gt; = iolist() | binary()</pre></li><li><pre>&lt;a name="type-data"&gt;data()&lt;/a&gt; = iolist() | binary()</pre></li><li><pre>&lt;a name="type-mac"&gt;mac()&lt;/a&gt; = binary()</pre></li></ul>

Compute a SHA MAC message authentication code from key and data.
<a name="hmac-4"></a>

###hmac/4##


<pre>hmac(Key :: <a href="#type-key">key()</a>,Data :: <a href="#type-data">data()</a>,Hash :: <a href="#type-hash">hash()</a>,Blocksize :: <a href="#type-blocksize">blocksize()</a>) -><a href="#type-mac">mac()</a></pre>
<ul class="definitions"><li><pre>&lt;a name="type-key"&gt;key()&lt;/a&gt; = iolist() | binary()</pre></li><li><pre>&lt;a name="type-data"&gt;data()&lt;/a&gt; = iolist() | binary()</pre></li><li><pre>&lt;a name="type-hash"&gt;hash()&lt;/a&gt; = fun((binary()) -&gt; binary())</pre></li><li><pre>&lt;a name="type-blocksize"&gt;blocksize()&lt;/a&gt; = non_neg_integer()</pre></li><li><pre>&lt;a name="type-mac"&gt;mac()&lt;/a&gt; = binary()</pre></li></ul>

Compute a SHA MAC message authentication code from key and data using
the specified hash function and blocksize.
<a name="hmac224-2"></a>

###hmac224/2##


<pre>hmac224(Key :: <a href="#type-key">key()</a>, Data :: <a href="#type-data">data()</a>) -> <a href="#type-mac">mac()</a></pre>
<ul class="definitions"><li><pre>&lt;a name="type-key"&gt;key()&lt;/a&gt; = iolist() | binary()</pre></li><li><pre>&lt;a name="type-data"&gt;data()&lt;/a&gt; = iolist() | binary()</pre></li><li><pre>&lt;a name="type-mac"&gt;mac()&lt;/a&gt; = binary()</pre></li></ul>

Compute a SHA-224 MAC message authentication code from key and data.
<a name="hmac256-2"></a>

###hmac256/2##


<pre>hmac256(Key :: <a href="#type-key">key()</a>, Data :: <a href="#type-data">data()</a>) -> <a href="#type-mac">mac()</a></pre>
<ul class="definitions"><li><pre>&lt;a name="type-key"&gt;key()&lt;/a&gt; = iolist() | binary()</pre></li><li><pre>&lt;a name="type-data"&gt;data()&lt;/a&gt; = iolist() | binary()</pre></li><li><pre>&lt;a name="type-mac"&gt;mac()&lt;/a&gt; = binary()</pre></li></ul>

Compute a SHA-256 MAC message authentication code from key and data.
<a name="hmac384-2"></a>

###hmac384/2##


<pre>hmac384(Key :: <a href="#type-key">key()</a>, Data :: <a href="#type-data">data()</a>) -> <a href="#type-mac">mac()</a></pre>
<ul class="definitions"><li><pre>&lt;a name="type-key"&gt;key()&lt;/a&gt; = iolist() | binary()</pre></li><li><pre>&lt;a name="type-data"&gt;data()&lt;/a&gt; = iolist() | binary()</pre></li><li><pre>&lt;a name="type-mac"&gt;mac()&lt;/a&gt; = binary()</pre></li></ul>

Compute a SHA-384 MAC message authentication code from key and data.
<a name="hmac512-2"></a>

###hmac512/2##


<pre>hmac512(Key :: <a href="#type-key">key()</a>, Data :: <a href="#type-data">data()</a>) -> <a href="#type-mac">mac()</a></pre>
<ul class="definitions"><li><pre>&lt;a name="type-key"&gt;key()&lt;/a&gt; = iolist() | binary()</pre></li><li><pre>&lt;a name="type-data"&gt;data()&lt;/a&gt; = iolist() | binary()</pre></li><li><pre>&lt;a name="type-mac"&gt;mac()&lt;/a&gt; = binary()</pre></li></ul>

Compute a SHA-512 MAC message authentication code from key and data.
