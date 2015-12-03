package shieldsjared.apps.spark.sparkwindowspki.ssl;

import java.awt.FlowLayout;
import java.awt.event.WindowAdapter;
import java.awt.event.WindowEvent;
import java.io.ByteArrayInputStream;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.Principal;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.Security;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Enumeration;

import javax.net.ssl.X509KeyManager;
import javax.security.auth.callback.Callback;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.callback.PasswordCallback;
import javax.security.auth.callback.UnsupportedCallbackException;
import javax.swing.JDialog;
import javax.swing.JLabel;
import javax.swing.JOptionPane;
import javax.swing.JPanel;
import javax.swing.JPasswordField;
import javax.swing.SwingUtilities;

public class WindowsSelectorKeyManager implements X509KeyManager, CallbackHandler {
	
	private String choosenAlias = null;
	private final Object keyStoreLock = new Object();
	private KeyStore keyStore;
	
	private static void initializePkcs11Provider() {
		try {
			String configPath = null;
			if(System.getProperty("sun.arch.data.model") == "64")
				 configPath = System.getProperty("user.dir") + "\\security64.config";
			else
				configPath = System.getProperty("user.dir") + "\\security.config";
			Provider acProvider = new sun.security.pkcs11.SunPKCS11(new FileInputStream(configPath));
			Security.addProvider(acProvider);
		} catch (FileNotFoundException e) {
			e.printStackTrace();
			System.exit(-1);
		}
	}
	
	public WindowsSelectorKeyManager(String choosenAlias) {
		super();
		this.choosenAlias = choosenAlias;
	}
	
	public WindowsSelectorKeyManager() {
		this(null);
	}
	
	public void setChoosenAlias(String alias) {
		this.choosenAlias = alias;
	}
	
	private KeyStore getKeyStore() {
		synchronized (keyStoreLock) {
			if (keyStore != null) {
				return keyStore;
			}
			try {
				keyStore = accessKeyStore();
			} catch(KeyStoreException e) {
				SwingUtilities.invokeLater(new Runnable() {
					@Override
					public void run() {
						JOptionPane.showMessageDialog(null, "There was an error retrieving certificates from your smart card.  Ensure it is inserted and try again.", "Failed", JOptionPane.ERROR_MESSAGE);
					}
				});
			} catch (Exception e) {
				reportAndConvert(e);
			}
			return keyStore;
		}
	}
	
	protected KeyStore accessKeyStore() throws Exception {
		KeyStore.CallbackHandlerProtection chp = new KeyStore.CallbackHandlerProtection(this);
		KeyStore.Builder builder = KeyStore.Builder.newInstance("PKCS11", null, chp);
		try {
			builder.getKeyStore();
		} catch(KeyStoreException e) {
			initializePkcs11Provider();
		}
		KeyStore result = builder.getKeyStore();
		result.load(null, null);
		return result;
	}

	@Override
	public synchronized String chooseClientAlias(final String[] keyType, final Principal[] issuers, Socket socket) {	
		System.out.println("Called: chooseClientAlias()  Returning: " + this.choosenAlias);
		return this.choosenAlias;
	}
	
	public CertDescription[] makeCertList(String[] aliases) {
		if (keyStore == null) {
			return new CertDescription[] { 
				new CertDescription(null, "<No Identifies Found>"),
			};
		}
		
		CertDescription[] result = new CertDescription[aliases.length];
		for (int i = 0; i < aliases.length; i++) {
			final String alias = aliases[i]; 
			result[i] = new CertDescription(alias,alias);
		}
		return result;
	}

	@Override
	public X509Certificate[] getCertificateChain(String alias) {
		try {
			return (X509Certificate[]) getKeyStore().getCertificateChain(alias);
		} catch (KeyStoreException e) {
			throw reportAndConvert(e);
		}
	}

	@Override
	public String[] getClientAliases(String keyType, Principal[] issuers) {
		try {
			KeyStore ks = getKeyStore();
			if (ks == null) {
				return new String[0];
			}
			ArrayList<String> asList = new ArrayList<String>();			
			Enumeration<String> aliases = ks.aliases();
			while (aliases.hasMoreElements()) {
				String alias = aliases.nextElement();
				X509Certificate certificate = (X509Certificate)this.getKeyStore().getCertificate(alias);
				if(issuers != null)
				{
					for(Principal issuer : issuers) {
						if(issuer.getName().equalsIgnoreCase(certificate.getIssuerX500Principal().getName()))
							asList.add(alias);
					}
				}
				else
				{
					asList.add(alias);
				}	
			}
			return asList.toArray(new String[asList.size()]);
		} catch (KeyStoreException e) {
			throw reportAndConvert(e);
		}
	}

	@Override
	public PrivateKey getPrivateKey(String alias) {
		try {
			return (PrivateKey) getKeyStore().getKey(alias, null);
		} catch (Exception e) {
			throw reportAndConvert(e);
		}
	}

	@Override
	public String chooseServerAlias(String keyType, Principal[] issuers, Socket socket) {
		throw new UnsupportedOperationException("Client manager only");
	}
	
	@Override
	public String[] getServerAliases(String keyType, Principal[] issuers) {
		throw new UnsupportedOperationException("Client manager only");
	}
	
	protected RuntimeException reportAndConvert(final Exception e) {
		SwingUtilities.invokeLater(new Runnable() {
			@Override
			public void run() {
				JOptionPane.showMessageDialog(null, e.getLocalizedMessage(), "Failed", JOptionPane.ERROR_MESSAGE);
			}
		});
		e.printStackTrace();
		return new RuntimeException(e);
		
	}

	@Override
	public void handle(Callback[] callbacks) throws IOException, UnsupportedCallbackException 
	{
		if(callbacks == null)
			return;
		
		for(int i = 0; i < callbacks.length; i++) {
			handle(callbacks[i]);
		}
	}
	
	public void handle(Callback callback) throws IOException, UnsupportedCallbackException
	{
		if(callback instanceof PasswordCallback) {
			PasswordCallback pc = (PasswordCallback)callback;
			
			final PasswordPanel pPnl = new PasswordPanel();
			final JOptionPane op = new JOptionPane(pPnl, JOptionPane.OK_CANCEL_OPTION, JOptionPane.PLAIN_MESSAGE);
			final JDialog dlg = op.createDialog("Enter your CAC PIN:");
			dlg.addWindowFocusListener(new WindowAdapter() {
			    @Override
			    public void windowGainedFocus(WindowEvent e) {
			        pPnl.gainedFocus();
			    }
			});
			pc.setPassword(pPnl.getPassword());			
		} else {
			throw new UnsupportedCallbackException(callback);
		}
	}
	
	private class PasswordPanel extends JPanel {
		private static final long serialVersionUID = 1L;
		private final JPasswordField passwordField = new JPasswordField(8);
		  private boolean gainedFocusBefore;

		  void gainedFocus() {
		    if (!gainedFocusBefore) {
		      gainedFocusBefore = true;
		      passwordField.requestFocusInWindow();
		    }
		  }

		  public PasswordPanel() {
		    super(new FlowLayout());

		    add(new JLabel("PIN: "));
		    add(passwordField);
		  }

		  public char[] getPassword() {
		      return passwordField.getPassword();
		  }
	}

	
}