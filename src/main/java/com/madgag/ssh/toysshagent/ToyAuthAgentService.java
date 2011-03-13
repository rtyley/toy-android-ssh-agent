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

import static com.google.common.collect.Maps.newHashMap;

import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Security;
import java.util.Map;

import net.schmizz.sshj.common.Base64;

import org.spongycastle.jce.provider.BouncyCastleProvider;
import org.spongycastle.openssl.PEMReader;

import android.app.Service;
import android.content.Intent;
import android.os.IBinder;
import android.os.RemoteException;
import android.util.Log;

import com.madgag.ssh.android.authagent.AndroidAuthAgent;

public class ToyAuthAgentService extends Service {
	
	private static final String TAG = "ToyAgentService";

	static {
		Security.addProvider(new BouncyCastleProvider());
	}
	
	private SshUtil sshUtil = new SshUtil();
	private KeyPair keyPair;
	
	@Override
	public void onCreate() {
		super.onCreate();
		try {
			InputStream privateRsaKeyStream = getAssets().open("id_rsa");
			PEMReader r = new PEMReader(new InputStreamReader(privateRsaKeyStream));
			keyPair = (KeyPair) r.readObject();
			Log.d(TAG, "onCreate - made "+keyPair);
		} catch (IOException e) {
			Log.e(TAG, "Failed to load key", e);
		}
	}
	
	@Override
	public IBinder onBind(Intent intent) {
		Log.d(TAG, "onBind() called");
		return authAgentBinder;
	}

	private final AndroidAuthAgent.Stub authAgentBinder = new AndroidAuthAgent.Stub() {

		public Map getIdentities() throws RemoteException {
			Log.d(TAG, "getIdentities() called");
			Map<String, byte[]> identityMap = newHashMap();
			
			PublicKey publicKey = keyPair.getPublic();
			byte[] keyEncodedInOpenSslFormat = sshUtil.sshEncode(publicKey);
			Log.i(TAG, "keyEncodedInOpenSslFormat="+Base64.encodeBytes(keyEncodedInOpenSslFormat));
			identityMap.put("idento", keyEncodedInOpenSslFormat);
			return identityMap;
		}

		public byte[] sign(byte[] publicKey, byte[] data) throws RemoteException {
			Log.d(TAG, "sign() called");
			//if (Arrays.equals(keyPair.getPublic().getEncoded(), publicKey)) {	
			PrivateKey privateKey = keyPair.getPrivate();
			return sshUtil.sign(data, privateKey);
		}

	};
}
