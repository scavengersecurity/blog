---
layout: post
title: "BambooFox CTF 2021 – Time to Draw [Web]"
categories: ctf
tags: web nodejs prototype-pullution javascript 00xc
date: 2021-01-21 19:00:00 +0100
author: 00xc
---

Time to Draw is a web challenge based on Node.js. The main page presented a canvas on which one could draw by clicking on it, and several buttons on the right side. One of those buttons showed the backend source code, which you can check [here](https://gist.github.com/00xc/dce4ade28c640019273de2c877b024be).

Looking at the `/flag` endpoint, we clearly need to send a `token` parameter along with our request; the hash (in this case, SHA256) of our source IP address concatenated with that token must match `userData.token`. If we are set as an admin (which we can do by visiting `/promote?yo_i_want_to_be=admin`), `userData.token` will contain some secret token, otherwise it will be undefined.

```javascript
let userData = { isGuest: true };
if (req.signedCookies.user && req.signedCookies.user.admin === true) {
	userData.isGuest = false;
	userData.isAdmin = req.cookies.admin;
	userData.token = secret.ADMIN_TOKEN;	// <<<--- uninitialized otherwise
}

if (req.query.token && req.query.token.match(/[0-9a-f]{16}/) &&
hash(`${req.connection.remoteAddress}${req.query.token}`) === userData.token) {
	res.send(secret.FLAG);
} else {
	res.send("NO");
}
```

It is this use of a possibly uninitialized variable that made us think about [JavaScript prototype pollution](https://blog.0daylabs.com/2019/02/15/prototype-pollution-javascript/). 

Prototypes are the JavaScript way of dealing with object inheritance. The attributes of objects in JavaScript are simply key-value pairs; these keys can be set by an object and then inherited by all other objects deriving from it, but these children can also overload its value. Each existing object in JavaScript has a `__proto__` member which points back to its parent. The parent of regular JavaScript objects is the base `Object`. Changes made to this base `Object` can be seen by every object that inherits from it.

Take the following snippet:

```javascript
first_obj = {};
first_obj.__proto__.vuln = "POLLUTED";
another_obj = {};
console.log(another_obj.vuln); // This prints "POLLUTED"
```

Here, the `vuln` attribute of `Object` was modified, and all other objects see this change, unless they themselves overwrite their `vuln` attribute. Now the question is how to pollute the `token` attribute so that we can control it when it is used uninitialized. Thankfully, this code in the `/api/draw` endpoint is vulnerable:

```javascript
app.get('/api/draw', (req, res) => {
	let { x, y, color } = req.query;
	if (x && y && color) canvas[x][y] = color.toString();
	res.json(canvas);
});
```

Its intended use, of course, is to change the color of one pixel in the canvas, given two coordinates and the desired color. However, in JavaScript, these two statements are equivalent:

```javascript
object['some']['thing'] = 'something';
object.some.thing = 'something';
```

Meaning that we can pollute the prototype as described above, using the `x` and `y` parameters. We can pick a token that matches the regex used (for example, 16 a’s), and then compute the hash of our public IP address concatenated to that token. Once that is done, we can pollute the prototype by visiting `/api/draw?x=__proto__&y=token&color=our_hash`. That request is processed as:

```javascript
canvas['__proto__']['token'] = our_hash
```

With the token polluted, we then trigger the vulnerability by visiting `/flag?token=aaaaaaaaaaaaaaaa`, which outputs the flag `flag{baby.__proto__.pollution.js}`.