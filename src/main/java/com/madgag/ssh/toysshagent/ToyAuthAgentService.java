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

import android.app.Service;
import android.content.Intent;
import android.os.IBinder;
import android.os.RemoteException;
import android.util.Log;
import com.madgag.ssh.android.authagent.AndroidAuthAgent;
import org.spongycastle.jce.provider.BouncyCastleProvider;
import org.spongycastle.openssl.PEMReader;

import java.io.IOException;
import java.io.InputStreamReader;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Security;
import java.util.Arrays;
import java.util.Map;

import static com.google.common.collect.Maps.newHashMap;

public class ToyAuthAgentService extends Service {
	
	private static final String TAG = "ToyAgentService";

	static {
		Security.addProvider(new BouncyCastleProvider());
	}
	
	private SshUtil sshUtil = new SshUtil();
    Map<String, byte[]> sshEncodedPublicKeys = newHashMap();
    Map<PublicKey, PrivateKey> publicPrivateMap = newHashMap();
	
	@Override
	public void onCreate() {
		super.onCreate();
        for (String privateKeyFileName : new String[] {"id_rsa", "id_dsa"}) {
            KeyPair keyPair = loadKey(privateKeyFileName);
            sshEncodedPublicKeys.put(privateKeyFileName, sshUtil.sshEncode(keyPair.getPublic()));
            publicPrivateMap.put(keyPair.getPublic(),keyPair.getPrivate());
        }
    }

    private KeyPair loadKey(String fileName) {
        try {
            PEMReader r = new PEMReader(new InputStreamReader(getAssets().open(fileName)));
            return (KeyPair) r.readObject();
        } catch (IOException e) {
            Log.e(TAG, "Failed to load key from "+fileName, e);
            throw new RuntimeException(e);
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
            return sshEncodedPublicKeys;
		}

		public byte[] sign(byte[] publicKey, byte[] data) throws RemoteException {
			Log.d(TAG, "sign() called");
            for (Map.Entry<PublicKey, PrivateKey> entry: publicPrivateMap.entrySet()) {
                if (Arrays.equals(sshUtil.sshEncode(entry.getKey()), publicKey)) {
                    return sshUtil.sign(data, entry.getValue());
                }
            }
            throw new RuntimeException("No key found matching requested public key");
		}

	};
}
