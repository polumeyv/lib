#!/usr/bin/env bun

const keyPair = await crypto.subtle.generateKey('Ed25519', true, ['sign', 'verify']);

const privateDer = await crypto.subtle.exportKey('pkcs8', keyPair.privateKey);
const publicDer = await crypto.subtle.exportKey('spki', keyPair.publicKey);

const toBase64 = (buf) => btoa(String.fromCharCode(...new Uint8Array(buf)));

const wrapPem = (label, b64) => {
	const lines = b64.match(/.{1,64}/g).join('\n');
	return `-----BEGIN ${label}-----\n${lines}\n-----END ${label}-----`;
};

console.log('PRIVATE_JWT_KEY="' + wrapPem('PRIVATE KEY', toBase64(privateDer)).replace(/\n/g, '\\n') + '"');
console.log('PUBLIC_JWT_KEY="' + wrapPem('PUBLIC KEY', toBase64(publicDer)).replace(/\n/g, '\\n') + '"');
