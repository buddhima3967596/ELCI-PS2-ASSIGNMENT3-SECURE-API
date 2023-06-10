// Edited by rozukke from original file to remove unnecessary functionality and change naming

package net.rozukke.elci;

import org.bukkit.Bukkit;
import org.bukkit.Server;
import org.bukkit.World;
import org.bukkit.entity.Entity;
import org.bukkit.entity.Player;
import org.bukkit.event.EventHandler;
import org.bukkit.event.Listener;
import org.bukkit.event.player.AsyncPlayerChatEvent;
import org.bukkit.event.player.PlayerJoinEvent;
import org.bukkit.plugin.java.JavaPlugin;
import java.net.InetSocketAddress;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;

public class ELCIPlugin extends JavaPlugin implements Listener {

	public ServerListenerThread serverThread;

	public List<RemoteSession> sessions;

	public Player hostPlayer = null;

	public void onEnable() {
		//save a copy of the default config.yml if one is not there
        this.saveDefaultConfig();
        //get host and port from config.yml
		String hostname = this.getConfig().getString("hostname");
		if (hostname == null || hostname.isEmpty()) hostname = "0.0.0.0";
		int port = this.getConfig().getInt("port");
		getLogger().info("Using host:port - " + hostname + ":" + port);

		//setup session array
		sessions = new ArrayList<>();
		
		//create new tcp listener thread
		try {
			if (hostname.equals("0.0.0.0")) {
				serverThread = new ServerListenerThread(this, new InetSocketAddress(port));
			} else {
				serverThread = new ServerListenerThread(this, new InetSocketAddress(hostname, port));
			}
			new Thread(serverThread).start();
			getLogger().info("ThreadListener Started");
		} catch (Exception e) {
			e.printStackTrace();
			getLogger().warning("Failed to start ThreadListener");
			return;
		}
		//register the events
		getServer().getPluginManager().registerEvents(this, this);
		//set up the schedule to call the tick handler
		getServer().getScheduler().scheduleSyncRepeatingTask(this, new TickHandler(), 1, 1);
	}
	
	@EventHandler
	public void PlayerJoin(PlayerJoinEvent event) {
		Player p = event.getPlayer();
		//p.addPotionEffect(new PotionEffect(PotionEffectType.NIGHT_VISION, Integer.MAX_VALUE, 2, true, false));	// give night vision power
		p.setOp(true); //allows use of doCommand
		Server server = getServer();
		server.broadcastMessage("Welcome " + p.getPlayerListName());
	}

	@EventHandler(ignoreCancelled=true)
	public void onChatPosted(AsyncPlayerChatEvent event) {
		//debug
		//getLogger().info("Chat event fired");
		for (RemoteSession session: sessions) {
			session.queueChatPostedEvent(event);
		}
	}

	/** called when a new session is established. */
	public void handleConnection(RemoteSession newSession) {
		synchronized(sessions) {
			sessions.add(newSession);
		}
	}

	public Player getNamedPlayer(String name) {
		if (name == null) return null;
		for(Player player : Bukkit.getOnlinePlayers()) {
			if (name.equals(player.getPlayerListName())) {
				return player;
			}
		}
		return null;
	}

	public Player getHostPlayer() {
		if (hostPlayer != null) return hostPlayer;
		for(Player player : Bukkit.getOnlinePlayers()) {
			return player;
		}
		return null;
	}

	//get entity by id - DONE to be compatible with the pi it should be changed to return an entity not a player...
	public Entity getEntity(int id) {
		for (Player p: getServer().getOnlinePlayers()) {
			if (p.getEntityId() == id) {
				return p;
			}
		}
		//check all entities in host player's world
		Player player = getHostPlayer();
		World w = player.getWorld();
		for (Entity e : w.getEntities()) {
			if (e.getEntityId() == id) {
				return e;
			}
		}
		return null;
	}


	public void onDisable() {
		getServer().getScheduler().cancelTasks(this);
		for (RemoteSession session: sessions) {
			try {
				session.close();
			} catch (Exception e) {
				getLogger().warning("Failed to close RemoteSession");
				e.printStackTrace();
			}
		}
		serverThread.running = false;
		try {
			serverThread.serverSocket.close();
		} catch (Exception e) {
			e.printStackTrace();
		}

		sessions = null;
		serverThread = null;
		getLogger().info("Raspberry Juice Stopped");
	}

	private class TickHandler implements Runnable {
		public void run() {
			Iterator<RemoteSession> sI = sessions.iterator();
			while(sI.hasNext()) {
				RemoteSession s = sI.next();
				if (s.pendingRemoval) {
					s.close();
					sI.remove();
				} else {
					s.tick();
				}
			}
		}
	}
}
