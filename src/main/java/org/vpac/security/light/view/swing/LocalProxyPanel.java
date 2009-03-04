package org.vpac.security.light.view.swing;

import java.awt.Cursor;
import java.awt.GridBagConstraints;
import java.awt.GridBagLayout;
import java.awt.Insets;

import javax.swing.JButton;
import javax.swing.JComboBox;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.JPasswordField;

import org.vpac.security.light.plainProxy.LocalProxy;
import org.vpac.security.light.utils.ActionPerformedListener;

public class LocalProxyPanel extends JPanel {

	public static final String[] DEFAULT_LIFETIMES = new String[]{"1", "2", "7", "14", "21"};
	

	
	private static final long serialVersionUID = 1L;
	private JLabel TitleLabel = null;
	private JLabel passphraseLabel = null;
	private JPasswordField passphraseField = null;
	private JButton jButton = null;
	private JButton jButton1 = null;
	private JLabel lifetimeLabel = null;
	private JComboBox lifetimeComboBox = null;
	
	public static final String CREATED_NAME = "Local Proxy created.";
	public static final String CANCEL_NAME = "Proxy creation aborted.";

	private ActionPerformedListener listener = null;
	private String[] lifetimes = null;

	/**
	 * This is the default constructor
	 */
	public LocalProxyPanel(ActionPerformedListener listener) {
		super();
		this.listener = listener;
		this.lifetimes = DEFAULT_LIFETIMES;
		initialize();

	}
	
	public LocalProxyPanel(ActionPerformedListener listener, String[] lifetimes) {
		super();
		this.listener = listener;
		this.lifetimes = lifetimes;
		initialize();
	}

	/**
	 * This method initializes this
	 * 
	 * @return void
	 */
	private void initialize() {
		GridBagConstraints lifetimeComboBoxConstraints = new GridBagConstraints();
		lifetimeComboBoxConstraints.fill = GridBagConstraints.HORIZONTAL;
		lifetimeComboBoxConstraints.gridy = 3;
		lifetimeComboBoxConstraints.weightx = 1.0;
		lifetimeComboBoxConstraints.gridwidth = 3;
		lifetimeComboBoxConstraints.insets = new Insets(15, 15, 0, 15);
		lifetimeComboBoxConstraints.gridx = 1;
		GridBagConstraints lifetimeLabelConstraints = new GridBagConstraints();
		lifetimeLabelConstraints.gridx = 0;
		lifetimeLabelConstraints.insets = new Insets(15, 15, 0, 0);
		lifetimeLabelConstraints.anchor = GridBagConstraints.WEST;
		lifetimeLabelConstraints.gridwidth = 1;
		lifetimeLabelConstraints.gridy = 3;
		lifetimeLabel = new JLabel();
		lifetimeLabel.setText("Specify the lifetime of the proxy (days):");
		GridBagConstraints cancelButtonConstraints = new GridBagConstraints();
		cancelButtonConstraints.gridx = 2;
		cancelButtonConstraints.anchor = GridBagConstraints.EAST;
		cancelButtonConstraints.weightx = 1.0;
		cancelButtonConstraints.insets = new Insets(20, 0, 0, 15);
		cancelButtonConstraints.fill = GridBagConstraints.NONE;
		cancelButtonConstraints.gridy = 4;
		GridBagConstraints okButtonConstraints = new GridBagConstraints();
		okButtonConstraints.gridx = 3;
		okButtonConstraints.insets = new Insets(20, 0, 0, 15);
		okButtonConstraints.gridy = 4;
		GridBagConstraints passphraseFieldConstraints = new GridBagConstraints();
		passphraseFieldConstraints.fill = GridBagConstraints.HORIZONTAL;
		passphraseFieldConstraints.gridy = 2;
		passphraseFieldConstraints.weightx = 1.0;
		passphraseFieldConstraints.insets = new Insets(0, 15, 0, 15);
		passphraseFieldConstraints.anchor = GridBagConstraints.WEST;
		passphraseFieldConstraints.gridwidth = 4;
		passphraseFieldConstraints.gridx = 0;
		GridBagConstraints passphraseLabelConstraints = new GridBagConstraints();
		passphraseLabelConstraints.gridx = 0;
		passphraseLabelConstraints.insets = new Insets(5, 15, 10, 0);
		passphraseLabelConstraints.anchor = GridBagConstraints.WEST;
		passphraseLabelConstraints.gridwidth = 4;
		passphraseLabelConstraints.gridy = 1;
		passphraseLabel = new JLabel();
		passphraseLabel.setText("Please enter the passphrase of your private key:");
		GridBagConstraints titleConstraints = new GridBagConstraints();
		titleConstraints.gridx = 0;
		titleConstraints.anchor = GridBagConstraints.WEST;
		titleConstraints.insets = new Insets(15, 15, 15, 0);
		titleConstraints.gridwidth = 3;
		titleConstraints.gridy = 0;
		TitleLabel = new JLabel();
		TitleLabel.setText("Grid proxy init");
		this.setSize(424, 312);
		this.setLayout(new GridBagLayout());
		this.add(TitleLabel, titleConstraints);
		this.add(passphraseLabel, passphraseLabelConstraints);
		this.add(getPassphraseField(), passphraseFieldConstraints);
		this.add(getJButton(), okButtonConstraints);
		this.add(getJButton1(), cancelButtonConstraints);
		this.add(lifetimeLabel, lifetimeLabelConstraints);
		this.add(getLifetimeComboBox(), lifetimeComboBoxConstraints);
	}

	/**
	 * This method initializes passphraseField	
	 * 	
	 * @return javax.swing.JPasswordField	
	 */
	private JPasswordField getPassphraseField() {
		if (passphraseField == null) {
			passphraseField = new JPasswordField();
		}
		return passphraseField;
	}

	/**
	 * This method initializes jButton	
	 * 	
	 * @return javax.swing.JButton	
	 */
	private JButton getJButton() {
		if (jButton == null) {
			jButton = new JButton();
			jButton.setText("Init");
			jButton.addActionListener(new java.awt.event.ActionListener() {
				public void actionPerformed(java.awt.event.ActionEvent e) {
					
					int lifetime_in_hours = -1;
					//LocalProxyPanel.this.setCursor(Cursor.getPredefinedCursor(Cursor.WAIT_CURSOR));
					try {
						lifetime_in_hours = new Integer((String)getLifetimeComboBox().getSelectedItem())*24;
					} catch (NumberFormatException e1) {
						LocalProxyPanel.this.setCursor(Cursor.getPredefinedCursor(Cursor.DEFAULT_CURSOR));
						Utils.showErrorMessage(LocalProxyPanel.this, "notANumber", e1);
					}
					
					try {
						LocalProxy.gridProxyInit(getPassphraseField().getPassword(), lifetime_in_hours);
						LocalProxyPanel.this.setCursor(Cursor.getPredefinedCursor(Cursor.DEFAULT_CURSOR));
						listener.success(CREATED_NAME, true, null);
					}  catch (Exception e1) {
						LocalProxyPanel.this.setCursor(Cursor.getPredefinedCursor(Cursor.DEFAULT_CURSOR));
						Utils.showErrorMessage(LocalProxyPanel.this, "localProxyCreationError", e1);
					}
					
				}
			});
			jButton.setText("Init");
		}
		return jButton;
	}

	/**
	 * This method initializes jButton1	
	 * 	
	 * @return javax.swing.JButton	
	 */
	private JButton getJButton1() {
		if (jButton1 == null) {
			jButton1 = new JButton();
			jButton1.setText("Cancel");
			jButton1.addActionListener(new java.awt.event.ActionListener() {
				public void actionPerformed(java.awt.event.ActionEvent e) {
					listener.success(CANCEL_NAME, true, null);
				}
			});
			jButton1.setText("Cancel");
		}
		return jButton1;
	}

	/**
	 * This method initializes lifetimeComboBox	
	 * 	
	 * @return javax.swing.JComboBox	
	 */
	private JComboBox getLifetimeComboBox() {
		if (lifetimeComboBox == null) {
			lifetimeComboBox = new JComboBox(lifetimes);
			lifetimeComboBox.setEditable(true);
		}
		return lifetimeComboBox;
	}



}  //  @jve:decl-index=0:visual-constraint="10,10"
