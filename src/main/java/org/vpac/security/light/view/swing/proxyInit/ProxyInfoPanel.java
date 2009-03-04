package org.vpac.security.light.view.swing.proxyInit;

import javax.swing.JLabel;
import javax.swing.JPanel;
import com.jgoodies.forms.factories.FormFactory;
import com.jgoodies.forms.layout.CellConstraints;
import com.jgoodies.forms.layout.ColumnSpec;
import com.jgoodies.forms.layout.FormLayout;
import com.jgoodies.forms.layout.RowSpec;

public class ProxyInfoPanel extends JPanel {

	private JLabel subjectLabel;
	/**
	 * Create the panel
	 */
	public ProxyInfoPanel() {
		super();
		setLayout(new FormLayout(
			new ColumnSpec[] {
				FormFactory.DEFAULT_COLSPEC,
				FormFactory.RELATED_GAP_COLSPEC,
				FormFactory.DEFAULT_COLSPEC},
			new RowSpec[] {
				FormFactory.DEFAULT_ROWSPEC,
				FormFactory.RELATED_GAP_ROWSPEC,
				FormFactory.DEFAULT_ROWSPEC}));
		add(getSubjectLabel(), new CellConstraints());
		//
	}
	/**
	 * @return
	 */
	protected JLabel getSubjectLabel() {
		if (subjectLabel == null) {
			subjectLabel = new JLabel();
			subjectLabel.setText("Subject");
		}
		return subjectLabel;
	}

}
