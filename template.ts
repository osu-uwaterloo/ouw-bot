import fs from 'fs';

const baseDir = './templates';

type TemplateData = {
    [key: string]: any;
};

export default function getTemplate(template: string, data: TemplateData = {}): string {
    const templatePath = `${baseDir}/${template}.html`;
    if (!fs.existsSync(templatePath)) {
        throw new Error(`Template not found: ${template}`);
    }

    let templateContent = fs.readFileSync(templatePath, 'utf-8');

    // Fill in data into template {{ key }}
    templateContent = templateContent.replace(/{{\s*([^}]+)\s*}}/g, (match, key) => {
        const content = data[key.trim()];
        if (content === undefined) {
            return "undefined";
        } else {
            return content.toString();
        }
    });

    // Replace relative paths
    templateContent = templateContent.replace(/"..\/static\//g, '"/static/');
    templateContent = templateContent.replace(/'..\/static\//g, "'/static/");
    templateContent = templateContent.replace(/=..\/static\//g, "='/static/");
    templateContent = templateContent.replace(/url\('..\/static\//g, "url('/static/");

    return templateContent;
}