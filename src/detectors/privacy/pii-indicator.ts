import type { Detector } from '../../core/types';
const piiPattern=/(email|phone|address|passport|national\s+id|ic\s+number)/i;
export const piiIndicator:Detector=({state})=>piiPattern.test(state)?[{id:'PII-001',severity:'low',title:'Possible personal-data context',detail:'Review whether personal data is necessary before model execution.',field:'state',detector:'pii-indicator'}]:[];