import env from './env.js';
import { EmbedBuilder, Client, ActionRowBuilder, GuildMember, ColorResolvable, TextChannel } from 'discord.js';

interface LoggerColors {
    info: string;
    warn: string;
    error: string;
    success: string;
    verbose: string;
}

type EmbedModifier = (embed: EmbedBuilder) => void;
type ActionRowConstructor = () => ActionRowBuilder<any> | undefined;

class Logger {
    private client: Client;
    private channel: string;
    private colour: LoggerColors;

    constructor(client: Client) {
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
    public log(
        colour: string,
        member: GuildMember | null,
        title: string,
        description: string,
        embedModifier: EmbedModifier = () => {},
        actionRowConstructor: ActionRowConstructor = () => undefined
    ): void {
        const embed = new EmbedBuilder()
            .setTitle(title)
            .setDescription(description)
            .setColor(colour as ColorResolvable)
            .setTimestamp();
        if (member) {
            try {
                embed.setAuthor({ name: member.user.tag, iconURL: member.user.displayAvatarURL(), url: `https://discord.com/users/${member.id}` });
                embed.setFooter({ text: `ID: ${member.id}` });
            } catch (e) { }
        }
        try { embedModifier(embed);} catch (e) { }
        const actionRow = actionRowConstructor();
        const textChannel = this.client.channels.cache.get(this.channel) as TextChannel;
        if (actionRow) {
            textChannel?.send({ embeds: [embed], components: [actionRow] });
        } else {
            textChannel?.send({ embeds: [embed] });
        }
    }
    public info(
        member: GuildMember | null,
        title: string,
        description: string,
        embedModifier: EmbedModifier = () => {},
        actionRowConstructor: ActionRowConstructor = () => undefined
    ): void {
        this.log(this.colour.info, member, title, description, embedModifier, actionRowConstructor);
    }
    public warn(
        member: GuildMember | null,
        title: string,
        description: string,
        embedModifier: EmbedModifier = () => {},
        actionRowConstructor: ActionRowConstructor = () => undefined
    ): void {
        this.log(this.colour.warn, member, title, description, embedModifier, actionRowConstructor);
    }
    public error(
        member: GuildMember | null,
        title: string,
        description: string,
        embedModifier: EmbedModifier = () => {},
        actionRowConstructor: ActionRowConstructor = () => undefined
    ): void {
        this.log(this.colour.error, member, title, description, embedModifier, actionRowConstructor);
    }
    public success(
        member: GuildMember | null,
        title: string,
        description: string,
        embedModifier: EmbedModifier = () => {},
        actionRowConstructor: ActionRowConstructor = () => undefined
    ): void {
        this.log(this.colour.success, member, title, description, embedModifier, actionRowConstructor);
    }
    public verbose(
        member: GuildMember | null,
        title: string,
        description: string,
        embedModifier: EmbedModifier = () => {},
        actionRowConstructor: ActionRowConstructor = () => undefined
    ): void {
        this.log(this.colour.verbose, member, title, description, embedModifier, actionRowConstructor);
    }
}

export default Logger;