Vagrant.configure(2) do |config|
  config.vbguest.installer_options = { allow_kernel_upgrade: true }
  config.vm.provider "virtualbox" do |vb|
    vb.customize ["modifyvm", :id, "--uart1", "0x3F8", "4"]
    vb.customize ["modifyvm", :id, "--uartmode1", "file", File::NULL]
  end

  config.vm.define "admin" do |admin|
    admin.vm.box = "ubuntu/focal64"
    admin.vm.network "private_network", ip:"192.168.56.39"
    admin.vm.hostname = "admin"
    admin.vm.boot_timeout = 600
    admin.vm.provision "shell",
      path: "./scripts/admin_server_installation.sh"
  end

  config.vm.define "vault" do |vault|
    vault.vm.box = "ubuntu/focal64"
    vault.vm.network "private_network", ip:"192.168.56.40"
    vault.vm.hostname = "vault"
    vault.vm.boot_timeout = 600
    vault.vm.provision "shell",
      path: "./scripts/vault_server_installation.sh"
  end

  (1..2).each do |i|
    config.vm.define "server0#{i}" do |server|
      server.vm.box = "ubuntu/focal64"
      server.vm.network "private_network", ip:"192.168.56.4#{i}"
      server.vm.hostname = "server0#{i}"
      server.vm.boot_timeout = 600
      server.vm.provision "shell",
        path: "./scripts/vault_ssh_helper_installation.sh"
    end
  end
end
