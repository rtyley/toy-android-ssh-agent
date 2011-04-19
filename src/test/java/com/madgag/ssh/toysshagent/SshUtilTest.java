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

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.notNullValue;

import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.security.KeyPair;
import java.security.PublicKey;

import net.schmizz.sshj.common.Base64;

import org.junit.Before;
import org.junit.Test;
import org.spongycastle.openssl.PEMReader;

public class SshUtilTest {

	SshUtil sshUtil = new SshUtil();
	KeyPair rsaKeyPair,dsaKeyPair;
	
	@Before
	public void setup() throws Exception {
        rsaKeyPair = loadKeyPair("/assets/id_rsa");
        dsaKeyPair = loadKeyPair("/assets/id_dsa");
	}

    private KeyPair loadKeyPair(String name) throws IOException {
        InputStream privateRsaKeyStream = SshUtil.class.getResourceAsStream(name);
        assertThat(privateRsaKeyStream, notNullValue());
        PEMReader r = new PEMReader(new InputStreamReader(privateRsaKeyStream));
        return (KeyPair) r.readObject();
    }

    @Test
	public void shouldEncodeSshKeysCorrectly() throws Exception {
		PublicKey publicKey = rsaKeyPair.getPublic();
		byte[] keyEncodedInOpenSshFormat = sshUtil.sshEncode(publicKey);
		String keyCorrectlyEncodedInSshFormat="AAAAB3NzaC1yc2EAAAADAQABAAABAQC8aO4pVPJglaCsmkV4CBY/IIPVSaNDhT6+bj7CgBw9adoZ/xu9tWVMMsW6nTOp4rCf9f5DjEsSgmGJoNd9lQeXILIIAl9PFtc+/RpQ59C1kCj1hDOQu5HNYo3KtWsAX8yGdJ1jweeL8xm0o2RSH0RbCWNz71vnFVxVqpaToXbTe4TBRxvqvkNPlw5P7fIs5c4flXRSLm/379xdM2Z/atat5+IUFtuEje0SCzWjnZ05SG0q4Efg4nWpWfY5VMHhvaeRfY9qsI8R8sWpb0lIp8aEUpaNV0HTTbMa3MlRuKk4g8VwY9OmyYvwyLYYMnpyvCo03H/jcnnlqbfb1wvsY+gT";
		
		assertThat(Base64.encodeBytes(keyEncodedInOpenSshFormat), equalTo(keyCorrectlyEncodedInSshFormat));
	}

    @Test
	public void shouldRoundTripEncodingKeys() throws Exception {
		assertThat(sshUtil.sshDecode(sshUtil.sshEncode(rsaKeyPair.getPublic())), equalTo(rsaKeyPair.getPublic()));
	}

	@Test
	public void shouldEncodeSignatures() throws Exception {
		byte[] dataToSign = Base64.decode("AAAAFKt3+AmyWTVYzKRV7J40wjc5jMe7MgAAAAAAAAAOc3NoLWNvbm5lY3Rpb24AAAAJcHVibGlja2V5AQAAAAdzc2gtcnNhAAABFwAAAAdzc2gtcnNhAAAAAwEAAQAAAQEAvGjuKVTyYJWgrJpFeAgWPyCD1UmjQ4U+vm4+woAcPWnaGf8bvbVlTDLFup0zqeKwn/X+Q4xLEoJhiaDXfZUHlyCyCAJfTxbXPv0aUOfQtZAo9YQzkLuRzWKNyrVrAF/MhnSdY8Hni/MZtKNkUh9EWwljc+9b5xVcVaqWk6F203uEwUcb6r5DT5cOT+3yLOXOH5V0Ui5v9+/cXTNmf2rWrefiFBbbhI3tEgs1o52dOUhtKuBH4OJ1qVn2OVTB4b2nkX2ParCPEfLFqW9JSKfGhFKWjVdB002zGtzJUbipOIPFcGPTpsmL8Mi2GDJ6crwqNNx/43J55am329cL7GPoEw==");
		byte[] signatureEncodedInOpenSshFormat = sshUtil.sign(dataToSign, rsaKeyPair.getPrivate());
		String signatureCorrectlyEncodedInSshFormat="AAAAB3NzaC1yc2EAAAEAH9hwEXcTfYfG8iau0ZefTWPAkMwXwOgr1ZQ2nZpCAZT+lBlFIGfa6dpfux+wo8pWT6nZ9sTFUYmmjYuJrjgwIGo2Zfh6QBBvSu0WDT8vG5l6BKbJTjfpnTYjgpMaBpx8ryh7MnRr6VDcu6JvfmenFtSulPPdIFFrf70448XXzU+x6uOv+6+Bg66wyVSL89UGIZSIaj/1UuW6Nz4sAzmlLCt6Ew36BC9PGO2dE5Skfm06Hjj8F9DK5J+XquitOAoz88QkTUJlMy2CgkD5/Y0MLGYn1qmnGCgGcfEwYe9uUJ7jc1nzyt9hK7arI/Uf2N8zLRUSQUW5uNMt8uYkDp6fjw==";
		assertThat(Base64.encodeBytes(signatureEncodedInOpenSshFormat), equalTo(signatureCorrectlyEncodedInSshFormat));
	}
}
