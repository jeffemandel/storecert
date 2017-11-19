import java.io.FileInputStream;
import java.io.FileReader;
import java.nio.file.*;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.SQLException;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.util.Properties;
import java.util.InvalidPropertiesFormatException;
import java.io.FileNotFoundException;
import java.nio.charset.StandardCharsets;
import java.io.File;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import javax.crypto.NoSuchPaddingException;
import java.util.Arrays;
import java.util.Base64;
import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;
import java.io.IOException;
import java.security.cert.X509Certificate;
import java.security.cert.CertificateFactory;
import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.security.cert.CertificateException;

public class storecert {

	public String certdir;
	public Connection conn;
	public String[] servers;
    private static SecretKeySpec secretKey;
	
	public storecert() {
        Properties properties = new Properties();

        try
        {
            // Load our configurations
            properties.loadFromXML(new FileInputStream("configuration.xml"));
            conn = DriverManager.getConnection(properties.getProperty("url"));
            certdir = properties.getProperty("certdir");
			servers = new File(certdir).list();
			System.out.println("In directory " + certdir);
			for (String server : servers) {
				System.out.println(server);
			}
			// Turn password into a secretKey
			byte[] key = properties.getProperty("password").getBytes("UTF-8");
			MessageDigest sha = MessageDigest.getInstance("SHA-1");
			key = sha.digest(key);
			key = Arrays.copyOf(key, 16);
			secretKey = new SecretKeySpec(key, "AES");
		} catch (NoSuchAlgorithmException ex) {
			System.err.println("No such algorithm: " + ex.getMessage());
		} catch (FileNotFoundException ex) {
			System.err.println("File not found: " + ex.getMessage());
		} catch (InvalidPropertiesFormatException ex) {
			System.err.println("Invalid properties format: " + ex.getMessage());
		} catch (SQLException e) {
			System.err.println("SQL Error: " + e.getMessage());
		} catch (Exception e) {
			System.err.println(e.getClass().getName()+": "+e.getMessage());
		}
    }

    public String encrypt(String strToEncrypt)
    {
        try
        {
            Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
            cipher.init(Cipher.ENCRYPT_MODE, secretKey);
            return Base64.getEncoder().encodeToString(cipher.doFinal(strToEncrypt.getBytes("UTF-8")));
        } catch (NoSuchAlgorithmException ex) {
			System.err.println("No such algorithm: " + ex.getMessage());
		} catch (NoSuchPaddingException ex) {
			System.err.println("No such padding: " + ex.getMessage());
		} catch (Exception e) {
			System.err.println(e.getClass().getName()+": "+e.getMessage());
		}
		return null;
    }
    
    public String decrypt(String strToDecrypt)
    {
        try
        {
            Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
            cipher.init(Cipher.DECRYPT_MODE, secretKey);
            return new String(cipher.doFinal(Base64.getDecoder().decode(strToDecrypt)));
        } catch (NoSuchAlgorithmException ex) {
			System.err.println("No such algorithm: " + ex.getMessage());
		} catch (NoSuchPaddingException ex) {
			System.err.println("No such padding: " + ex.getMessage());
		} catch (Exception e) {
			System.err.println(e.getClass().getName()+": "+e.getMessage());
		}
		return null;
    }
    
    public String loadCert(String server, String certname) {
    	String contents=null;
        try {
        	// Construct a path for the PEM
        	Path myFile = Paths.get(certdir, server, certname.concat(".pem"));
        	System.out.println(myFile.toString());
            // Return AES encrypted certificate
            contents = encrypt(new String(Files.readAllBytes(myFile)));
        } catch (Exception e) {
            e.printStackTrace();
        }
        return contents;
    
    }
    
    
    public void insertDB(String server) {
    
        try {
        	String privkey = loadCert(server, "privkey");
        	String cert = loadCert(server, "cert");
        	String chain = loadCert(server, "chain");
        	String fullchain = loadCert(server, "fullchain");
        	// Use the Postgresql 9.5+ UPSERT
        	String statement = 
        	"insert into certstore (cert,chain,fullchain,privkey,server) " +
        	" values (?,?,?,?,?) " +
			" ON CONFLICT ON CONSTRAINT server_key " +
			" DO UPDATE SET cert=EXCLUDED.cert, " +
			" chain=EXCLUDED.chain, " +
			" fullchain=EXCLUDED.fullchain, " +
			" privkey=EXCLUDED.privkey";
        	
			PreparedStatement st = conn.prepareStatement(statement);
			st.setString(1, cert);
			st.setString(2, chain);
			st.setString(3, fullchain);
			st.setString(4, privkey);
			st.setString(5, server);
			st.executeUpdate();
			st.close();
		} catch (SQLException e) {
			System.err.println("SQL Error: " + e.getMessage());
		}
    }
    
   public void readDB(String server) {
    
        try {
			PreparedStatement st = conn.prepareStatement("SELECT cert,chain,fullchain,privkey from certstore where server=?");
			st.setString(1, server);
			ResultSet rs = st.executeQuery();
			rs.next();
        	saveCert(server, "privkey", rs.getString("privkey"));
        	saveDER(server, "cert", rs.getString("cert"));
        	saveCert(server, "chain", rs.getString("chain"));
        	saveCert(server, "fullchain", rs.getString("fullchain"));
			st.close();
		} catch (SQLException e) {
			System.err.println("SQL Error: " + e.getMessage());
		} catch (IOException e) {
			System.err.println("IOException error: " + e.getMessage());
		}
    }

    public void saveCert(String server, String certname, String encrypted) throws IOException {
    	String theKey = decrypt(encrypted);
        Files.write(Paths.get(certdir, server, certname.concat(".pem")), theKey.getBytes());
    }

    public void saveDER(String server, String certname, String encrypted) throws IOException {
    	String theKey = decrypt(encrypted);
        Files.write(Paths.get(certdir, server, certname.concat(".pem")), theKey.getBytes());

		try {
		CertificateFactory cf = CertificateFactory.getInstance("X.509");
		InputStream stream = new ByteArrayInputStream(theKey.getBytes(StandardCharsets.UTF_8));
		X509Certificate myCert = (X509Certificate)cf.generateCertificate(stream);
// 		PemReader certReader = new PemReader(new StringReader(theKey));
// 		X509Certificate myCert = (X509Certificate) certReader.readPemObject();
        Files.write(Paths.get(certdir, server, certname.concat(".der")), myCert.getEncoded());
        } catch (CertificateException ex) {
			System.err.println("CertificateException error: " + ex.getMessage());
        }
    
    }

    public static void main(String[] args){
    	storecert myInstance = new storecert();
    	try {
			Class.forName("org.postgresql.Driver");
        } catch (ClassNotFoundException e) {
        	System.out.println("Class not found: " + e.getMessage() + "\n Add postgresql-xx.jar to classpath");
        }
    	if (args.length == 1) {
    		switch (args[0]) {
    			case "--store":
					for (String server : myInstance.servers) {
						myInstance.insertDB(server);
					}
					break;
    			case "--load" :
					for (String server : myInstance.servers) {
						myInstance.readDB(server);
					}
					break;
    			default :
    				System.out.println("usage: storecert --store|--load");
    		}
    	} else {
    		System.out.println("usage: storecert --store|--load");
        }
    }
}