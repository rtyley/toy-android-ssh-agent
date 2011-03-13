/*
 * Copyright (c) 2011 Roberto Tyley
 *
 * This file is part of 'Toy Android ssh-agent'.
 *
 * 'Toy Android ssh-agent' is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * 'Toy Android ssh-agent' is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with 'Toy Android ssh-agent'.  If not, see <http://www.gnu.org/licenses/>.
 */

package com.madgag.ssh.toysshagent;

import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Security;
import java.security.Signature;
import java.security.SignatureException;

import net.schmizz.sshj.common.Buffer.PlainBuffer;
import net.schmizz.sshj.common.KeyType;

import org.spongycastle.jce.provider.BouncyCastleProvider;

public class SshUtil {
	static {
		Security.addProvider(new BouncyCastleProvider());
	}
	
	public byte[] sshEncode(PublicKey publicKey) {
		return new PlainBuffer().putPublicKey(publicKey).getCompactData();
	}
	
	public byte[] sign(byte[] data, PrivateKey privateKey) {
		String keyTypeName = KeyType.fromKey(privateKey).toString();
		try {
			return new PlainBuffer().putString(keyTypeName).putBytes(rawSignatureFor(data, privateKey)).getCompactData();
		} catch (Exception e) {
			throw new RuntimeException(e);
		}
	}

	byte[] rawSignatureFor(byte[] data, PrivateKey privateKey)
			throws NoSuchAlgorithmException, InvalidKeyException,
			SignatureException {
		Signature signer = Signature.getInstance("SHA1withRSA");
		signer.initSign(privateKey);
		signer.update(data);
		return signer.sign();
	}

}
