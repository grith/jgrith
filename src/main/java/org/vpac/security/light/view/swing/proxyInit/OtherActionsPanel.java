package org.vpac.security.light.view.swing.proxyInit;

import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.io.File;
import java.io.IOException;

import javax.swing.JButton;
import javax.swing.JLabel;
import javax.swing.JOptionPane;
import javax.swing.JPanel;

import org.apache.log4j.Logger;
import org.globus.gsi.GlobusCredential;
import org.globus.myproxy.InitParams;
import org.globus.myproxy.MyProxy;
import org.globus.myproxy.MyProxyException;
import org.vpac.security.light.CredentialHelpers;
import org.vpac.security.light.myProxy.MyProxy_light;
import org.vpac.security.light.plainProxy.LocalProxy;
import org.vpac.security.light.view.swing.MyProxyUploadDialog;

import au.org.arcs.commonInterfaces.ProxyCreatorHolder;
import au.org.arcs.commonInterfaces.ProxyDestructorHolder;

import com.jgoodies.forms.factories.FormFactory;
import com.jgoodies.forms.layout.CellConstraints;
import com.jgoodies.forms.layout.ColumnSpec;
import com.jgoodies.forms.layout.FormLayout;
import com.jgoodies.forms.layout.RowSpec;

public class OtherActionsPanel extends JPanel {
	
	private static final Logger myLogger = Logger.getLogger(OtherActionsPanel.class.getName());
	
	private JButton loadLocalProxyButton;
	private JLabel label;
	public static final MyProxy DEFAULT_MYPROXY = new MyProxy("myproxy.arcs.org.au", 443);
	
	private ProxyDestructorHolder destructionHolder = null;
	private ProxyCreatorHolder creationHolder = null;
	
	private JButton destroyButton;
	private JButton uploadButton;
	private JButton storeButton;
	private JLabel destroyLabel;
	private JLabel uploadCurrentProxyLabel;
	private JLabel storeLocalProxyLabel;
	
	private MyProxy myproxy = null;
	
	private GlobusCredential proxy = null;
	
	/**
	 * Create the panel
	 */
	public OtherActionsPanel(boolean hideLocalButtons) {
		super();
		setLayout(new FormLayout(
			new ColumnSpec[] {
				FormFactory.RELATED_GAP_COLSPEC,
				ColumnSpec.decode("default:grow(1.0)"),
				FormFactory.RELATED_GAP_COLSPEC,
				FormFactory.DEFAULT_COLSPEC,
				FormFactory.RELATED_GAP_COLSPEC,
				ColumnSpec.decode("default:grow(1.0)"),
				FormFactory.RELATED_GAP_COLSPEC,
				FormFactory.DEFAULT_COLSPEC,
				FormFactory.RELATED_GAP_COLSPEC},
			new RowSpec[] {
				FormFactory.RELATED_GAP_ROWSPEC,
				FormFactory.DEFAULT_ROWSPEC,
				FormFactory.RELATED_GAP_ROWSPEC,
				FormFactory.DEFAULT_ROWSPEC,
				FormFactory.RELATED_GAP_ROWSPEC}));
		add(getUploadCurrentProxyLabel(), new CellConstraints(2, 2));
		add(getUploadButton(), new CellConstraints(4, 2));
		add(getDestroyButton(), new CellConstraints(8, 2));
		add(getDestroyLabel(), new CellConstraints(6, 2));
		if ( ! hideLocalButtons ) {
			add(getLabel(), new CellConstraints(2, 4));
			add(getStoreButton(), new CellConstraints(8, 4));
			add(getStoreLocalProxyLabel(), new CellConstraints(6, 4));
			add(getLoadLocalProxyButton(), new CellConstraints(4, 4));
		}
		//

		enablePanel(false);
		checkLocalProxy();
	}
	
	private void checkLocalProxy() {
		
		try {
			LocalProxy.loadGlobusCredential().verify();
			getLoadLocalProxyButton().setEnabled(true);
		} catch (Exception e) {
			getLoadLocalProxyButton().setEnabled(false);
		}
			
	}
	
	public void setProxyDescrutorHolder(ProxyDestructorHolder holder) {
		this.destructionHolder = holder;
	}
	
	public void setProxyCreationHolder(ProxyCreatorHolder holder) {
		this.creationHolder = holder;
		try {
			LocalProxy.loadGlobusCredential().verify();
			loadLocalProxy();
		} catch (Exception e) {
			getLoadLocalProxyButton().setEnabled(false);
		}
	}
	
	private void enablePanel(boolean enable) {
		
		getStoreButton().setEnabled(enable);
		getDestroyButton().setEnabled(enable);
		getUploadButton().setEnabled(enable);
		
	}
	
	public void setProxy(GlobusCredential proxy) {
		
		try {
			proxy.verify();
		} catch (Exception e) {
			this.proxy = null;
			enablePanel(false);
			return;
		}
		
		this.proxy = proxy;
		
		enablePanel(true);
		checkLocalProxy();
	}
	
	public MyProxy getMyproxy() {
		
		if ( myproxy == null ) {
			return DEFAULT_MYPROXY;
		}
		
		return myproxy;
	}
	
	public void setMyProxy(MyProxy myproxy) {
		this.myproxy = myproxy;
	}
	
	/**
	 * @return
	 */
	protected JLabel getStoreLocalProxyLabel() {
		if (storeLocalProxyLabel == null) {
			storeLocalProxyLabel = new JLabel();
			storeLocalProxyLabel.setText("Store as local proxy");
		}
		return storeLocalProxyLabel;
	}
	/**
	 * @return
	 */
	protected JLabel getUploadCurrentProxyLabel() {
		if (uploadCurrentProxyLabel == null) {
			uploadCurrentProxyLabel = new JLabel();
			uploadCurrentProxyLabel.setText("Upload to MyProxy");
		}
		return uploadCurrentProxyLabel;
	}
	/**
	 * @return
	 */
	protected JLabel getDestroyLabel() {
		if (destroyLabel == null) {
			destroyLabel = new JLabel();
			destroyLabel.setText("Destroy");
		}
		return destroyLabel;
	}
	/**
	 * @return
	 */
	protected JButton getStoreButton() {
		if (storeButton == null) {
			storeButton = new JButton();
			storeButton.setToolTipText("Stores the current proxy to the default location on your computer");
			storeButton.addActionListener(new ActionListener() {
				public void actionPerformed(final ActionEvent e) {
					
					try {
						CredentialHelpers.writeToDisk(proxy, new File(LocalProxy.PROXY_FILE));
						
						JOptionPane
						.showMessageDialog(
								OtherActionsPanel.this, "Proxy written successfully to: "+LocalProxy.PROXY_FILE,
								"I/O error",
								JOptionPane.INFORMATION_MESSAGE);
						
					} catch (IOException e1) {
						JOptionPane
						.showMessageDialog(
								OtherActionsPanel.this, e1
										.getLocalizedMessage(),
								"I/O error",
								JOptionPane.ERROR_MESSAGE);
					}
					
					checkLocalProxy();
					
				}
			});
			storeButton.setText("Store");
		}
		return storeButton;
	}
	/**
	 * @return
	 */
	protected JButton getUploadButton() {
		if (uploadButton == null) {
			uploadButton = new JButton();
			uploadButton.setToolTipText("Uploads the current proxy into MyProxy");
			uploadButton.addActionListener(new ActionListener() {
				public void actionPerformed(final ActionEvent e) {
					
					MyProxyUploadDialog mpud = new MyProxyUploadDialog();
					InitParams params;
					try {
						params = MyProxy_light.prepareProxyParameters(System.getProperty("user.name"), null, "*", "*", null, -1);
					} catch (MyProxyException e1) {
						JOptionPane
						.showMessageDialog(
								OtherActionsPanel.this, e1
										.getLocalizedMessage(),
								"MyProxy error",
								JOptionPane.ERROR_MESSAGE);
						return;
					}
					mpud.initialize(proxy, params, getMyproxy());
					mpud.setVisible(true);
					
					boolean success = mpud.isSuccess();
					
					if ( success ) {
						JOptionPane
						.showMessageDialog(
								OtherActionsPanel.this, "MyProxy upload successful.",
								"MyProxy success",
								JOptionPane.INFORMATION_MESSAGE);
					}
					mpud.dispose();
				}
			});
			uploadButton.setText("Upload");
		}
		return uploadButton;
	}
	/**
	 * @return
	 */
	protected JButton getDestroyButton() {
		if (destroyButton == null) {
			destroyButton = new JButton();
			destroyButton.setToolTipText("Destroys the current proxy and a possibly existing locally stored one");
			destroyButton.addActionListener(new ActionListener() {
				public void actionPerformed(final ActionEvent e) {
					
					LocalProxy.gridProxyDestroy();
					if ( destructionHolder != null ) {
						destructionHolder.destroyProxy();
					}
					
					checkLocalProxy();
					
				}
			});
			destroyButton.setText("Destroy");
		}
		return destroyButton;
	}
	/**
	 * @return
	 */
	protected JLabel getLabel() {
		if (label == null) {
			label = new JLabel();
			label.setText("Load local proxy");
		}
		return label;
	}
	/**
	 * @return
	 */
	protected JButton getLoadLocalProxyButton() {
		if (loadLocalProxyButton == null) {
			loadLocalProxyButton = new JButton();
			loadLocalProxyButton.setToolTipText("Loads a local proxy from the default location into this app");
			loadLocalProxyButton.addActionListener(new ActionListener() {
				public void actionPerformed(final ActionEvent e) {
					
					loadLocalProxy();
					
				}
			});
			loadLocalProxyButton.setText("Load");
		}
		return loadLocalProxyButton;
	}
	
	private void loadLocalProxy() {
		try {
			GlobusCredential proxy = LocalProxy.loadGlobusCredential();
			proxy.verify();
			creationHolder.proxyCreated(proxy);
		} catch (Exception e1) {
//			myLogger.warn("Couldn't load local proxy: "+e1);
			JOptionPane
			.showMessageDialog(
					OtherActionsPanel.this, "Could not load local proxy: "+e1.getLocalizedMessage(),
					"Proxy error",
					JOptionPane.ERROR_MESSAGE);
		}
	}
	/**
	 * @return
	 */

}
