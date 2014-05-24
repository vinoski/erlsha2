

# Module hmac #
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

## Function Index ##


<table width="100%" border="1" cellspacing="0" cellpadding="2" summary="function index"><tr><td valign="top"><a href="#hexlify-1">hexlify/1</a></td><td>Convert binary to equivalent hexadecimal string.</td></tr><tr><td valign="top"><a href="#hexlify-2">hexlify/2</a></td><td>Convert binary to equivalent hexadecimal string or binary depending
on the options passed in the second argument.</td></tr><tr><td valign="top"><a href="#hmac-2">hmac/2</a></td><td>Compute a SHA MAC message authentication code from key and data.</td></tr><tr><td valign="top"><a href="#hmac-4">hmac/4</a></td><td>Compute a SHA MAC message authentication code from key and data using
the specified hash function and blocksize.</td></tr><tr><td valign="top"><a href="#hmac224-2">hmac224/2</a></td><td>Compute a SHA-224 MAC message authentication code from key and data.</td></tr><tr><td valign="top"><a href="#hmac256-2">hmac256/2</a></td><td>Compute a SHA-256 MAC message authentication code from key and data.</td></tr><tr><td valign="top"><a href="#hmac384-2">hmac384/2</a></td><td>Compute a SHA-384 MAC message authentication code from key and data.</td></tr><tr><td valign="top"><a href="#hmac512-2">hmac512/2</a></td><td>Compute a SHA-512 MAC message authentication code from key and data.</td></tr></table>


<a name="functions"></a>

## Function Details ##

<a name="hexlify-1"></a>

### hexlify/1 ###


<pre><code>
hexlify(Binary :: binary()) -&gt; list()
</code></pre>


Convert binary to equivalent hexadecimal string.

<a name="hexlify-2"></a>

### hexlify/2 ###


<pre><code>
hexlify(Binary :: binary(), Opts :: <a href="#type-hmac_opts">hmac_opts()</a>) -&gt;string() | binary()
</code></pre>


Convert binary to equivalent hexadecimal string or binary depending
on the options passed in the second argument. If the options list
contains the atom 'string' a string is returned, or if the option
'binary' is passed a binary is returned. If the options list contains
the atom 'upper' then the alphabetic hexadecimal characters in the
return value are uppercase, or if the option 'lower' is passed then the
alphabetic hexadecimal characters in the return value are lowercase. The
default if no options are passed is to return an uppercase string.

<a name="hmac-2"></a>

### hmac/2 ###


<pre><code>
hmac(Key :: <a href="#type-key">key()</a>, Data :: <a href="#type-data">data()</a>) -&gt; <a href="#type-mac">mac()</a>
</code></pre>

<ul class="definitions"><li><code><a name="type-key">key()</a> = iolist() | binary()</code></li><li><code><a name="type-data">data()</a> = iolist() | binary()</code></li><li><code><a name="type-mac">mac()</a> = binary()</code></li></ul>

Compute a SHA MAC message authentication code from key and data.

<a name="hmac-4"></a>

### hmac/4 ###


<pre><code>
hmac(Key :: <a href="#type-key">key()</a>,Data :: <a href="#type-data">data()</a>,Hash :: <a href="#type-hash">hash()</a>,Blocksize :: <a href="#type-blocksize">blocksize()</a>) -&gt;<a href="#type-mac">mac()</a>
</code></pre>

<ul class="definitions"><li><code><a name="type-key">key()</a> = iolist() | binary()</code></li><li><code><a name="type-data">data()</a> = iolist() | binary()</code></li><li><code><a name="type-hash">hash()</a> = fun((binary()) -&gt; binary())</code></li><li><code><a name="type-blocksize">blocksize()</a> = non_neg_integer()</code></li><li><code><a name="type-mac">mac()</a> = binary()</code></li></ul>

Compute a SHA MAC message authentication code from key and data using
the specified hash function and blocksize.

<a name="hmac224-2"></a>

### hmac224/2 ###


<pre><code>
hmac224(Key :: <a href="#type-key">key()</a>, Data :: <a href="#type-data">data()</a>) -&gt; <a href="#type-mac">mac()</a>
</code></pre>

<ul class="definitions"><li><code><a name="type-key">key()</a> = iolist() | binary()</code></li><li><code><a name="type-data">data()</a> = iolist() | binary()</code></li><li><code><a name="type-mac">mac()</a> = binary()</code></li></ul>

Compute a SHA-224 MAC message authentication code from key and data.

<a name="hmac256-2"></a>

### hmac256/2 ###


<pre><code>
hmac256(Key :: <a href="#type-key">key()</a>, Data :: <a href="#type-data">data()</a>) -&gt; <a href="#type-mac">mac()</a>
</code></pre>

<ul class="definitions"><li><code><a name="type-key">key()</a> = iolist() | binary()</code></li><li><code><a name="type-data">data()</a> = iolist() | binary()</code></li><li><code><a name="type-mac">mac()</a> = binary()</code></li></ul>

Compute a SHA-256 MAC message authentication code from key and data.

<a name="hmac384-2"></a>

### hmac384/2 ###


<pre><code>
hmac384(Key :: <a href="#type-key">key()</a>, Data :: <a href="#type-data">data()</a>) -&gt; <a href="#type-mac">mac()</a>
</code></pre>

<ul class="definitions"><li><code><a name="type-key">key()</a> = iolist() | binary()</code></li><li><code><a name="type-data">data()</a> = iolist() | binary()</code></li><li><code><a name="type-mac">mac()</a> = binary()</code></li></ul>

Compute a SHA-384 MAC message authentication code from key and data.

<a name="hmac512-2"></a>

### hmac512/2 ###


<pre><code>
hmac512(Key :: <a href="#type-key">key()</a>, Data :: <a href="#type-data">data()</a>) -&gt; <a href="#type-mac">mac()</a>
</code></pre>

<ul class="definitions"><li><code><a name="type-key">key()</a> = iolist() | binary()</code></li><li><code><a name="type-data">data()</a> = iolist() | binary()</code></li><li><code><a name="type-mac">mac()</a> = binary()</code></li></ul>

Compute a SHA-512 MAC message authentication code from key and data.

