package grith.jgrith.view.swing;

import grisu.jcommons.model.info.VO;
import grith.jgrith.utils.CredentialHelpers;
import grith.jgrith.vomsProxy.VomsException;
import grith.jgrith.vomsProxy.VomsHelpers;
import grith.jgrith.vomsProxy.VomsProxy;

import java.awt.GridBagConstraints;
import java.awt.GridBagLayout;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.util.Enumeration;
import java.util.Map;
import java.util.Set;
import java.util.Vector;

import javax.swing.DefaultComboBoxModel;
import javax.swing.JButton;
import javax.swing.JComboBox;
import javax.swing.JOptionPane;
import javax.swing.JPanel;

import org.ietf.jgss.GSSCredential;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class VomsInfoPanel extends JPanel {

	static final Logger myLogger = LoggerFactory.getLogger(VomsInfoPanel.class
			.getName());

	private JButton initButton;
	private JComboBox groupComboBox;
	private JComboBox voComboBox;

	private GSSCredential credential = null;
	private VomsProxy currentVomsProxy = null;
	Map<VO, Set<String>> info = null;
	DefaultComboBoxModel voModel = new DefaultComboBoxModel();
	DefaultComboBoxModel groupModel = new DefaultComboBoxModel();

	String buttonText = "Init";
	boolean ignoreErrors = true;

	// -------------------------------------------------------------------
	// EventStuff
	private Vector<ProxyInitListener> vomsPanelListeners;

	/**
	 * Creates the VomsInfoPanel. You have to register a listener to get the
	 * newly created voms credential after the button is pressed.
	 * 
	 * @param buttonText
	 *            the text for the init button. If you specify null, "Init" is
	 *            used.
	 * @param ignoreErrors
	 *            whether to stop querying for voms information if an error with
	 *            one of the servers occurs or not.
	 */
	public VomsInfoPanel() {
		super();
		final GridBagLayout gridBagLayout = new GridBagLayout();
		gridBagLayout.columnWidths = new int[] { 0 };
		gridBagLayout.rowHeights = new int[] { 0, 7, 7, 7, 7, 7 };
		setLayout(gridBagLayout);
		final GridBagConstraints gridBagConstraints = new GridBagConstraints();
		gridBagConstraints.fill = GridBagConstraints.HORIZONTAL;
		gridBagConstraints.weightx = 1.0;
		gridBagConstraints.gridy = 0;
		gridBagConstraints.gridx = 0;
		add(getVoComboBox(), gridBagConstraints);
		final GridBagConstraints gridBagConstraints_1 = new GridBagConstraints();
		gridBagConstraints_1.fill = GridBagConstraints.HORIZONTAL;
		gridBagConstraints_1.weightx = 1.0;
		gridBagConstraints_1.gridy = 2;
		gridBagConstraints_1.gridx = 0;
		add(getGroupComboBox(), gridBagConstraints_1);
		final GridBagConstraints gridBagConstraints_2 = new GridBagConstraints();
		gridBagConstraints_2.anchor = GridBagConstraints.SOUTHEAST;
		gridBagConstraints_2.gridy = 5;
		gridBagConstraints_2.gridx = 0;
		add(getInitButton(), gridBagConstraints_2);
		//

	}

	// register a listener
	synchronized public void addVomsPanelListener(ProxyInitListener l) {
		if (vomsPanelListeners == null) {
			vomsPanelListeners = new Vector();
		}
		vomsPanelListeners.addElement(l);
	}

	public void disablePanel(boolean disable) {

		if (disable) {
			getVoComboBox().setEnabled(false);
			getGroupComboBox().setEnabled(false);
			getInitButton().setEnabled(false);
		} else {
			getVoComboBox().setEnabled(true);
			getGroupComboBox().setEnabled(true);
			getInitButton().setEnabled(true);
		}

	}

	private void fireNewProxyCreated(VomsProxy vomsProxy) {
		// if we have no mountPointsListeners, do nothing...
		if ((vomsPanelListeners != null) && !vomsPanelListeners.isEmpty()) {
			// create the event object to send

			// make a copy of the listener list in case
			// anyone adds/removes mountPointsListeners
			Vector targets;
			synchronized (this) {
				targets = (Vector) vomsPanelListeners.clone();
			}

			// walk through the listener list and
			// call the gridproxychanged method in each
			Enumeration e = targets.elements();
			while (e.hasMoreElements()) {
				ProxyInitListener l = (ProxyInitListener) e.nextElement();
				l.proxyCreated(vomsProxy.getVomsProxyCredential());
			}
		}
	}

	public String getCurrentlySelectedGroup() {
		return (String) groupModel.getSelectedItem();
	}

	public VO getCurrentlySelectedVO() {

		return (VO) voModel.getSelectedItem();
	}

	/**
	 * @return
	 */
	protected JComboBox getGroupComboBox() {
		if (groupComboBox == null) {
			groupComboBox = new JComboBox(groupModel);
		}
		return groupComboBox;
	}

	/**
	 * @return
	 */
	protected JButton getInitButton() {
		if (initButton == null) {
			initButton = new JButton();
			initButton.addActionListener(new ActionListener() {
				public void actionPerformed(final ActionEvent e) {

					try {
						initProxy();
					} catch (Exception e1) {
						myLogger.error("Voms error: "
								+ e1.getLocalizedMessage());
						JOptionPane.showMessageDialog(VomsInfoPanel.this,
								e1.getLocalizedMessage(), "Voms error",
								JOptionPane.ERROR_MESSAGE);
					}

				}
			});
			initButton.setText("Init");
		}
		return initButton;
	}

	/**
	 * @return
	 */
	protected JComboBox getVoComboBox() {
		if (voComboBox == null) {
			voComboBox = new JComboBox(voModel);
		}
		return voComboBox;
	}

	public void initialize(String buttonText, boolean ignoreErrors) {
		if ((buttonText != null) && !"".equals(buttonText)) {
			this.buttonText = buttonText;
		}
		getInitButton().setText(this.buttonText);
		this.ignoreErrors = ignoreErrors;

	}

	private void initProxy() throws Exception {

		VO vo = getCurrentlySelectedVO();
		String group = getCurrentlySelectedGroup();
		long lifetime = credential.getRemainingLifetime() * 1000;

		currentVomsProxy = new VomsProxy(vo, group,
				CredentialHelpers.unwrapGlobusCredential(credential), lifetime);
		fireNewProxyCreated(currentVomsProxy);
	}

	/**
	 * You have to call this method to initialize the panel
	 * 
	 * @param credential
	 *            the credential
	 * @throws VomsException
	 *             if there is an error with one of the voms servers
	 */
	public void loadCredential(GSSCredential credential) throws VomsException {
		this.credential = credential;

		voModel.removeAllElements();
		groupModel.removeAllElements();

		info = VomsHelpers.getAllVosAndVoGroups(credential, ignoreErrors);

		for (VO vo : info.keySet()) {
			voModel.addElement(vo);
		}

		if (info.keySet().iterator().hasNext()) {
			setVO(info.keySet().iterator().next());
		}
	}

	// remove a listener
	synchronized public void removeVomsPanelListener(ProxyInitListener l) {
		if (vomsPanelListeners == null) {
			vomsPanelListeners = new Vector<ProxyInitListener>();
		}
		vomsPanelListeners.removeElement(l);
	}

	public void setVO(VO vo) {

		if (info == null) {
			myLogger.error("No info present. Can't set the VO. Ignoring the command.");
			return;
		}
		setVO(vo, info.get(vo).iterator().next());
	}

	public void setVO(VO vo, String group) {

		if (info == null) {
			myLogger.error("No info present. Can't set the VO. Ignoring the command.");
			return;
		}

		if (voModel.getIndexOf(vo) == -1) {
			myLogger.error("This VO is not available. Ignoring the command.");
			return;
		}
		voModel.setSelectedItem(vo);

		groupModel.removeAllElements();

		for (String voGroup : info.get(vo)) {
			groupModel.addElement(voGroup);
		}

		if (groupModel.getIndexOf(group) == -1) {
			myLogger.error("This group can't be selected. Ignoring the command.");
			return;
		} else {
			groupModel.setSelectedItem(group);
		}
	}

}
