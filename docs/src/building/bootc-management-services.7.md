# Management services

When running a fleet of systems, it is common to use a central management service. Commonly, these services provide a client to be installed on each system which connects to the central service. Often, the management service requires the client to perform a one time registration.

The following example shows how to install the client into a bootc image and run it at startup to register the system. This example assumes the management-client handles future connections to the server, e.g. via a cron job or a separate systemd service. This example could be modified to create a persistent systemd service if that is required. The Containerfile is not optimized in order to more clarly explain each step, e.g. it's generally better to invoke RUN a single time to avoid creating multiple layers in the image.

```Dockerfile
FROM <bootc base image>

# Typically when using a management service, it will determine when to upgrade the system.
# So, disable bootc-fetch-apply-updates.timer if it is included in the base image.
RUN systemctl disable bootc-fetch-apply-updates.timer

# Install the client from dnf, or some other method that applies for your client
RUN dnf install management-client -y && dnf clean all

# Bake the credentials for the management service into the image
ARG activation_key=

# The existence of .run_next_boot acts as a flag to determine if the
# registration is required to run when booting
RUN touch /etc/management-client/.run_next_boot

COPY <<"EOT" /usr/lib/systemd/system/management-client.service
[Unit]
Description=Run management client at boot
After=network-online.target
ConditionPathExists=/etc/management-client/.run_client_next_boot

[Service]
Type=oneshot
EnvironmentFile=/etc/management-client/.credentials
ExecStart=/usr/bin/management-client register --activation-key ${CLIENT_ACTIVATION_KEY}
ExecStartPre=/bin/rm -f /etc/management-client/.run_next_boot
ExecStop=/bin/rm -f /etc/management-client/.credentials

[Install]
WantedBy=multi-user.target
EOT

# Link the service to run at startup
RUN ln -s /usr/lib/systemd/system/management-client.service \
    /usr/lib/systemd/system/multi-user.target.wants/management-client.service

# Store the credentials in a file to be used by the systemd service
RUN echo -e "CLIENT_ACTIVATION_KEY=${activation_key}" > /etc/management-client/.credentials

# Set the flag to enable the service to run one time
# The systemd service will remove this file after the registration completes the first time
RUN touch /etc/management-client/.run_next_boot
```
