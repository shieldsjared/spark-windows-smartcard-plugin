package shieldsjared.apps.spark.sparkwindowspki;

import shieldsjared.apps.spark.sparkwindowspki.ui.LoginDialog;

import org.jivesoftware.spark.SparkManager;
import org.jivesoftware.spark.plugin.Plugin;
import org.jivesoftware.spark.preference.PreferenceManager;
import org.jivesoftware.spark.util.UIComponentRegistry;

public class WindowsPkiPlugin implements Plugin {
	
	public WindowsPkiPlugin() {
		UIComponentRegistry.registerLoginDialog(LoginDialog.class);
	}

	@Override
	public boolean canShutDown() {
		return true;
	}

	@Override
	public void initialize() {
	}

	@Override
	public void shutdown() {
	}

	@Override
	public void uninstall() {
		
	}

}
