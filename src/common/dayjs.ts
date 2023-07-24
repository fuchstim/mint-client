import dayjs from 'dayjs';
import timezone from 'dayjs/plugin/timezone';
import advancedFormat from 'dayjs/plugin/advancedFormat';

dayjs.extend(timezone);
dayjs.extend(advancedFormat);

export default dayjs;
