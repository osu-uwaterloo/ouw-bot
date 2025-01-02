import env from './env.js';
import { Client, GatewayIntentBits, EmbedBuilder, ButtonBuilder, ActionRowBuilder, ButtonStyle, PermissionFlagsBits } from 'discord.js';


class Logger {
    constructor(client) {
        this.client = client;
        this.channel = env.LOGGING_CHANNEL_ID;
        this.colour = {
            info: '#9dcbf7',
            warn: '#eea766',
            error: '#ff7d92',
            success: '#7ce87c',
            verbose: '#bbbbbb',
        };
    }
    log(colour, member, title, description, extraFields = [], actions = []) {
        // if extraFields is a dictionary, convert it to an array

        const embed = new EmbedBuilder()
            .setTitle(title)
            .setDescription(description)
            .setColor(colour)
            .setTimestamp();
        if (member) {
            embed.setAuthor({ name: member.user.tag, iconURL: member.user.displayAvatarURL(), url: `https://discord.com/users/${member.id}` });
            embed.setFooter({ text: `ID: ${member.id}` });
        }
        if (typeof extraFields === 'object' && !Array.isArray(extraFields)) {
            extraFields = [extraFields];
        }
        extraFields.forEach(field => {
            const { title, value, inline = true } = field;
            embed.addFields({ name: title, value, inline });
        });
        if (actions.length > 0) {
            const components = actions.map(action => {
                const { label, style = ButtonStyle.Secondary, id } = action;
                return new ButtonBuilder()
                    .setLabel(label)
                    .setStyle(style)
                    .setCustomId(id);
            });
            const row = new ActionRowBuilder().addComponents(components);
            embed.setActionRows(row);
            this.client.channels.cache.get(this.channel)?.send({ embeds: [embed], components: [row] });
        } else {
            this.client.channels.cache.get(this.channel)?.send({ embeds: [embed] });
        }
    }
    info(member, title, description, extraFields = [], actions = []) {
        this.log(this.colour.info, member, title, description, extraFields, actions);
    }
    warn(member, title, description, extraFields = [], actions = []) {
        this.log(this.colour.warn, member, title, description, extraFields, actions);
    }
    error(member, title, description, extraFields = [], actions = []) {
        this.log(this.colour.error, member, title, description, extraFields, actions);
    }
    success(member, title, description, extraFields = [], actions = []) {
        this.log(this.colour.success, member, title, description, extraFields, actions);
    }
    verbose(member, title, description, extraFields = [], actions = []) {
        this.log(this.colour.verbose, member, title, description, extraFields, actions);
    }
}

export default Logger;