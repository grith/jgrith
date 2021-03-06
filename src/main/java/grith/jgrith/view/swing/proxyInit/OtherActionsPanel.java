package grith.jgrith.view.swing.proxyInit;

import grisu.jcommons.commonInterfaces.ProxyCreatorHolder;
import grisu.jcommons.commonInterfaces.ProxyDestructorHolder;
import grith.jgrith.Environment;
import grith.jgrith.myProxy.MyProxy_light;
import grith.jgrith.plainProxy.LocalProxy;
import grith.jgrith.utils.CredentialHelpers;
import grith.jgrith.view.swing.MyProxyUploadDialog;

import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.io.File;
import java.io.IOException;

import javax.swing.JButton;
import javax.swing.JLabel;
import javax.swing.JOptionPane;
import javax.swing.JPanel;

import org.globus.gsi.GlobusCredential;
import org.globus.myproxy.InitParams;
import org.globus.myproxy.MyProxyException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.jgoodies.forms.layout.CellConstraints;
import com.jgoodies.forms.layout.ColumnSpec;
import com.jgoodies.forms.layout.FormLayout;
import com.jgoodies.forms.layout.FormSpecs;
import com.jgoodies.forms.layout.RowSpec;

public class OtherActionsPanel extends JPanel {

	private static final Logger myLogger = LoggerFactory
			.getLogger(OtherActionsPanel.class.getName());

	private JButton loadLocalProxyButton;
	private JLabel label;

	private ProxyDestructorHolder destructionHolder = null;
	private ProxyCreatorHolder creationHolder = null;

	private JButton destroyButton;
	private JButton uploadButton;
	private JButton storeButton;
	private JLabel destroyLabel;
	private JLabel uploadCurrentProxyLabel;
	private JLabel storeLocalProxyLabel;

	private GlobusCredential proxy = null;

	/**
	 * Create the panel
	 */
	public OtherActionsPanel(boolean hideLocalButtons) {
		super();
		setLayout(new FormLayout(new ColumnSpec[] {
				FormSpecs.RELATED_GAP_COLSPEC,
				ColumnSpec.decode("default:grow(1.0)"),
				FormSpecs.RELATED_GAP_COLSPEC, FormSpecs.DEFAULT_COLSPEC,
				FormSpecs.RELATED_GAP_COLSPEC,
				ColumnSpec.decode("default:grow(1.0)"),
				FormSpecs.RELATED_GAP_COLSPEC, FormSpecs.DEFAULT_COLSPEC,
				FormSpecs.RELATED_GAP_COLSPEC }, new RowSpec[] {
				FormSpecs.RELATED_GAP_ROWSPEC, FormSpecs.DEFAULT_ROWSPEC,
				FormSpecs.RELATED_GAP_ROWSPEC, FormSpecs.DEFAULT_ROWSPEC,
				FormSpecs.RELATED_GAP_ROWSPEC }));
		add(getUploadCurrentProxyLabel(), new CellConstraints(2, 2));
		add(getUploadButton(), new CellConstraints(4, 2));
		add(getDestroyButton(), new CellConstraints(8, 2));
		add(getDestroyLabel(), new CellConstraints(6, 2));
		if (!hideLocalButtons) {
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

	private void enablePanel(boolean enable) {

		getStoreButton().setEnabled(enable);
		getDestroyButton().setEnabled(enable);
		getUploadButton().setEnabled(enable);

	}

	/**
	 * @return
	 */
	protected JButton getDestroyButton() {
		if (destroyButton == null) {
			destroyButton = new JButton();
			destroyButton
			.setToolTipText("Destroys the current proxy and a possibly existing locally stored one");
			destroyButton.addActionListener(new ActionListener() {
				public void actionPerformed(final ActionEvent e) {

					LocalProxy.gridProxyDestroy();
					if (destructionHolder != null) {
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
			loadLocalProxyButton
			.setToolTipText("Loads a local proxy from the default location into this app");
			loadLocalProxyButton.addActionListener(new ActionListener() {
				public void actionPerformed(final ActionEvent e) {

					loadLocalProxy();

				}
			});
			loadLocalProxyButton.setText("Load");
		}
		return loadLocalProxyButton;
	}

	/**
	 * @return
	 */
	protected JButton getStoreButton() {
		if (storeButton == null) {
			storeButton = new JButton();
			storeButton
			.setToolTipText("Stores the current proxy to the default location on your computer");
			storeButton.addActionListener(new ActionListener() {
				public void actionPerformed(final ActionEvent e) {

					try {
						CredentialHelpers.writeToDisk(proxy, new File(
								LocalProxy.PROXY_FILE));

						JOptionPane.showMessageDialog(OtherActionsPanel.this,
								"Proxy written successfully to: "
										+ LocalProxy.PROXY_FILE, "I/O error",
										JOptionPane.INFORMATION_MESSAGE);

					} catch (IOException e1) {
						JOptionPane.showMessageDialog(OtherActionsPanel.this,
								e1.getLocalizedMessage(), "I/O error",
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
	protected JButton getUploadButton() {
		if (uploadButton == null) {
			uploadButton = new JButton();
			uploadButton
			.setToolTipText("Uploads the current proxy into MyProxy");
			uploadButton.addActionListener(new ActionListener() {
				public void actionPerformed(final ActionEvent e) {

					MyProxyUploadDialog mpud = new MyProxyUploadDialog();
					InitParams params;
					try {
						params = MyProxy_light.prepareProxyParameters(
								System.getProperty("user.name"), null, "*",
								"*", null, -1);
					} catch (MyProxyException e1) {
						JOptionPane.showMessageDialog(OtherActionsPanel.this,
								e1.getLocalizedMessage(), "MyProxy error",
								JOptionPane.ERROR_MESSAGE);
						return;
					}
					mpud.initialize(proxy, params,
							Environment.getDefaultMyProxy());
					mpud.setVisible(true);

					boolean success = mpud.isSuccess();

					if (success) {
						JOptionPane.showMessageDialog(OtherActionsPanel.this,
								"MyProxy upload successful.",
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
	protected JLabel getUploadCurrentProxyLabel() {
		if (uploadCurrentProxyLabel == null) {
			uploadCurrentProxyLabel = new JLabel();
			uploadCurrentProxyLabel.setText("Upload to MyProxy");
		}
		return uploadCurrentProxyLabel;
	}

	private void loadLocalProxy() {
		try {
			GlobusCredential proxy = LocalProxy.loadGlobusCredential();
			proxy.verify();
			creationHolder.proxyCreated(proxy);
		} catch (Exception e1) {
			// myLogger.warn("Couldn't load local proxy: "+e1);
			JOptionPane.showMessageDialog(OtherActionsPanel.this,
					"Could not load local proxy: " + e1.getLocalizedMessage(),
					"Proxy error", JOptionPane.ERROR_MESSAGE);
		}
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

	public void setProxyCreationHolder(ProxyCreatorHolder holder) {
		this.creationHolder = holder;
		try {
			LocalProxy.loadGlobusCredential().verify();
			loadLocalProxy();
		} catch (Exception e) {
			getLoadLocalProxyButton().setEnabled(false);
		}
	}

	public void setProxyDescrutorHolder(ProxyDestructorHolder holder) {
		this.destructionHolder = holder;
	}

}
