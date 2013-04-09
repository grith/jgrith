package grith.jgrith.view.swing.proxyInit;

import grisu.jcommons.commonInterfaces.ProxyCreatorHolder;
import grisu.model.info.dto.VO;
import grith.jgrith.utils.CredentialHelpers;
import grith.jgrith.voms.VOManagement.VOManagement;
import grith.jgrith.vomsProxy.VomsException;
import grith.jgrith.vomsProxy.VomsProxy;

import java.awt.Cursor;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.util.Map;

import javax.swing.DefaultComboBoxModel;
import javax.swing.JButton;
import javax.swing.JComboBox;
import javax.swing.JLabel;
import javax.swing.JOptionPane;
import javax.swing.JPanel;

import org.globus.gsi.GlobusCredential;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.jgoodies.forms.layout.CellConstraints;
import com.jgoodies.forms.layout.ColumnSpec;
import com.jgoodies.forms.layout.FormLayout;
import com.jgoodies.forms.layout.FormSpecs;
import com.jgoodies.forms.layout.RowSpec;

public class CreateVomsProxyPanel extends JPanel {

	private static final Logger myLogger = LoggerFactory
			.getLogger(CreateVomsProxyPanel.class);

	private JButton joinVoButton;
	private JComboBox comboBox;
	private JLabel label;

	private final DefaultComboBoxModel voModel = new DefaultComboBoxModel();

	Map<String, VO> allFqans = null;

	Thread fillThread = null;

	private GlobusCredential proxy = null;
	private ProxyCreatorHolder proxyCreatorHolder = null;

	private boolean denyComboboxUpdate = false;

	/**
	 * Create the panel
	 */
	public CreateVomsProxyPanel() {
		super();
		setLayout(new FormLayout(new ColumnSpec[] {
				FormSpecs.RELATED_GAP_COLSPEC,
				ColumnSpec.decode("default:grow(1.0)"),
				FormSpecs.RELATED_GAP_COLSPEC, FormSpecs.DEFAULT_COLSPEC,
				FormSpecs.RELATED_GAP_COLSPEC }, new RowSpec[] {
				FormSpecs.RELATED_GAP_ROWSPEC, FormSpecs.DEFAULT_ROWSPEC,
				FormSpecs.RELATED_GAP_ROWSPEC, FormSpecs.DEFAULT_ROWSPEC,
				FormSpecs.RELATED_GAP_ROWSPEC }));
		add(getLabel(), new CellConstraints(2, 2, 3, 1));
		add(getComboBox(), new CellConstraints(2, 4));
		add(getJoinVoButton(), new CellConstraints(4, 4));
		//
		enablePanel(false);
	}

	private void clearVoModel() {
		voModel.removeAllElements();
		voModel.addElement("n/a");
	}

	private void createVomsProxy() {

		new Thread() {
			@Override
			public void run() {
				try {

					enablePanel(false);
					CreateVomsProxyPanel.this.setCursor(Cursor
							.getPredefinedCursor(Cursor.WAIT_CURSOR));
					String fqan = (String) voModel.getSelectedItem();

					VO vo = getAllFqans().get(fqan);
					long lifetime;
					lifetime = CredentialHelpers.wrapGlobusCredential(proxy)
							.getRemainingLifetime() * 1000;
					VomsProxy newVomsProxy = new VomsProxy(vo, fqan, proxy,
							lifetime);

					denyComboboxUpdate = true;
					proxyCreatorHolder.proxyCreated(newVomsProxy
							.getVomsProxyCredential());
					denyComboboxUpdate = false;

				} catch (Exception e) {
					myLogger.error(
							"Can't create vomsProxy: "
									+ e.getLocalizedMessage(), e);
					CreateVomsProxyPanel.this.setCursor(Cursor
							.getPredefinedCursor(Cursor.DEFAULT_CURSOR));
					JOptionPane
					.showMessageDialog(
							CreateVomsProxyPanel.this,
							"<html><body>Error when trying to contact VOMRS.<br><br>This is a know bug. Destroy your proxy and try again until it works...</body></html>",
							"Voms error", JOptionPane.ERROR_MESSAGE);
					enablePanel(true);
					return;
				} finally {
					CreateVomsProxyPanel.this.setCursor(Cursor
							.getPredefinedCursor(Cursor.DEFAULT_CURSOR));

				}
			}

		}.start();

	}

	private void enablePanel(final boolean enable) {

		if (proxyCreatorHolder == null) {
			getComboBox().setEnabled(false);
			getJoinVoButton().setEnabled(false);
		} else if (enable == false) {
			getComboBox().setEnabled(false);
			getJoinVoButton().setEnabled(false);
			setCursor(Cursor.getPredefinedCursor(Cursor.DEFAULT_CURSOR));
		} else {

			if ((fillThread != null) && fillThread.isAlive()) {
				// I know, I know, shouldn't do that...
				fillThread.stop();
			}
			fillThread = new Thread() {
				@Override
				public void run() {

					getComboBox().setEnabled(false);

					getJoinVoButton().setEnabled(false);

					voModel.removeAllElements();

					boolean proxyAllRight = true;
					try {
						proxy.verify();
					} catch (Exception e) {
						proxyAllRight = false;
					}

					if (proxyAllRight && enable) {
						try {
							setCursor(Cursor
									.getPredefinedCursor(Cursor.WAIT_CURSOR));
							voModel.addElement("Loading your groups...");
							fillVOs();
							getComboBox().setEnabled(true);
							getJoinVoButton().setEnabled(true);
							setCursor(Cursor
									.getPredefinedCursor(Cursor.DEFAULT_CURSOR));
						} catch (VomsException e) {
							voModel.removeAllElements();
							voModel.addElement("Error: "
									+ e.getLocalizedMessage());
							setCursor(Cursor
									.getPredefinedCursor(Cursor.DEFAULT_CURSOR));
							getComboBox().setEnabled(false);
							getJoinVoButton().setEnabled(false);
						}
					} else {
						voModel.addElement("n/a");
						getComboBox().setEnabled(false);
						getJoinVoButton().setEnabled(false);
					}
				}
			};
			fillThread.start();
		}
	}

	private void fillVOs() throws VomsException {

		String oldFqan = (String) getComboBox().getSelectedItem();

		//
		// voModel.addElement(NON_VOMS_PROXY_NAME);
		Map<String, VO> tempAllFqans = getAllFqans();

		if (tempAllFqans == null) {
			throw new VomsException("Can't get list of fqans...");
		}
		voModel.removeAllElements();

		for (String fqan : tempAllFqans.keySet()) {
			voModel.addElement(fqan);
		}

		if (voModel.getIndexOf(oldFqan) >= 0) {
			voModel.setSelectedItem(oldFqan);
		}
	}

	private Map<String, VO> getAllFqans() {

		try {
			proxy.verify();
		} catch (Exception e) {
			myLogger.warn("No Proxy. Can't get fqans.");
			allFqans = null;
			return allFqans;
		}

		if (allFqans == null) {
			allFqans = VOManagement.getAllFqans(CredentialHelpers
					.wrapGlobusCredential(proxy));
		}
		return allFqans;
	}

	/**
	 * @return
	 */
	protected JComboBox getComboBox() {
		if (comboBox == null) {
			comboBox = new JComboBox(voModel);
			voModel.addElement("n/a");
		}
		return comboBox;
	}

	/**
	 * @return
	 */
	protected JButton getJoinVoButton() {
		if (joinVoButton == null) {
			joinVoButton = new JButton();
			joinVoButton.addActionListener(new ActionListener() {
				public void actionPerformed(final ActionEvent e) {

					createVomsProxy();

				}
			});
			joinVoButton.setText("Add Group");
		}
		return joinVoButton;
	}

	/**
	 * @return
	 */
	protected JLabel getLabel() {
		if (label == null) {
			label = new JLabel();
			label.setText("Please choose the group you want to use:");
		}
		return label;
	}

	public void setProxy(GlobusCredential proxy) {

		this.proxy = proxy;
		allFqans = null;
		if (proxy != null) {
			enablePanel(true);
		} else {
			if ((fillThread != null) && fillThread.isAlive()) {
				// I'm being a bad boy again...
				fillThread.stop();
			}
			enablePanel(false);
			clearVoModel();
		}
	}

	public void setProxyCreatorHolder(ProxyCreatorHolder holder) {
		this.proxyCreatorHolder = holder;
	}

	// public void proxyDestroyed() {
	//
	// this.proxy = null;
	// enablePanel(false);
	// clearVoModel();
	// }

}
