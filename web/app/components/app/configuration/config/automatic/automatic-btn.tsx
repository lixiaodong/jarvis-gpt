'use client'
import type { FC } from 'react'
import React from 'react'
import { useTranslation } from 'react-i18next'
import Button from '@/app/components/base/button'

export type IAutomaticBtnProps = {
  onClick: () => void
}

const leftIcon = (
  <svg width="14" height="14" viewBox="0 0 14 14" fill="none" xmlns="http://www.w3.org/2000/svg">
    <path d="M4.31346 0.905711C4.21464 0.708087 4.01266 0.583252 3.79171 0.583252C3.57076 0.583252 3.36877 0.708087 3.26996 0.905711L2.81236 1.82091C2.64757 2.15048 2.59736 2.24532 2.53635 2.32447C2.47515 2.40386 2.40398 2.47503 2.32459 2.53623C2.24544 2.59724 2.1506 2.64745 1.82103 2.81224L0.905833 3.26984C0.708209 3.36865 0.583374 3.57064 0.583374 3.79159C0.583374 4.01254 0.708209 4.21452 0.905833 4.31333L1.82103 4.77094C2.1506 4.93572 2.24544 4.98593 2.32459 5.04694C2.40398 5.10814 2.47515 5.17931 2.53635 5.2587C2.59736 5.33785 2.64758 5.43269 2.81236 5.76226L3.26996 6.67746C3.36877 6.87508 3.57076 6.99992 3.79171 6.99992C4.01266 6.99992 4.21465 6.87508 4.31346 6.67746L4.77106 5.76226C4.93584 5.43269 4.98605 5.33786 5.04707 5.2587C5.10826 5.17931 5.17943 5.10814 5.25883 5.04694C5.33798 4.98593 5.43282 4.93572 5.76238 4.77094L6.67758 4.31333C6.87521 4.21452 7.00004 4.01254 7.00004 3.79159C7.00004 3.57064 6.87521 3.36865 6.67758 3.26984L5.76238 2.81224C5.43282 2.64745 5.33798 2.59724 5.25883 2.53623C5.17943 2.47503 5.10826 2.40386 5.04707 2.32447C4.98605 2.24532 4.93584 2.15048 4.77106 1.82091L4.31346 0.905711Z" fill="#444CE7"/>
    <path d="M11.375 1.74992C11.375 1.42775 11.1139 1.16659 10.7917 1.16659C10.4695 1.16659 10.2084 1.42775 10.2084 1.74992V2.62492H9.33337C9.01121 2.62492 8.75004 2.88609 8.75004 3.20825C8.75004 3.53042 9.01121 3.79159 9.33337 3.79159H10.2084V4.66659C10.2084 4.98875 10.4695 5.24992 10.7917 5.24992C11.1139 5.24992 11.375 4.98875 11.375 4.66659V3.79159H12.25C12.5722 3.79159 12.8334 3.53042 12.8334 3.20825C12.8334 2.88609 12.5722 2.62492 12.25 2.62492H11.375V1.74992Z" fill="#444CE7"/>
    <path d="M3.79171 9.33325C3.79171 9.01109 3.53054 8.74992 3.20837 8.74992C2.88621 8.74992 2.62504 9.01109 2.62504 9.33325V10.2083H1.75004C1.42787 10.2083 1.16671 10.4694 1.16671 10.7916C1.16671 11.1138 1.42787 11.3749 1.75004 11.3749H2.62504V12.2499C2.62504 12.5721 2.88621 12.8333 3.20837 12.8333C3.53054 12.8333 3.79171 12.5721 3.79171 12.2499V11.3749H4.66671C4.98887 11.3749 5.25004 11.1138 5.25004 10.7916C5.25004 10.4694 4.98887 10.2083 4.66671 10.2083H3.79171V9.33325Z" fill="#444CE7"/>
    <path d="M10.4385 6.73904C10.3396 6.54142 10.1377 6.41659 9.91671 6.41659C9.69576 6.41659 9.49377 6.54142 9.39496 6.73904L8.84014 7.84869C8.67535 8.17826 8.62514 8.27309 8.56413 8.35225C8.50293 8.43164 8.43176 8.50281 8.35237 8.56401C8.27322 8.62502 8.17838 8.67523 7.84881 8.84001L6.73917 9.39484C6.54154 9.49365 6.41671 9.69564 6.41671 9.91659C6.41671 10.1375 6.54154 10.3395 6.73917 10.4383L7.84881 10.9932C8.17838 11.1579 8.27322 11.2082 8.35237 11.2692C8.43176 11.3304 8.50293 11.4015 8.56413 11.4809C8.62514 11.5601 8.67535 11.6549 8.84014 11.9845L9.39496 13.0941C9.49377 13.2918 9.69576 13.4166 9.91671 13.4166C10.1377 13.4166 10.3396 13.2918 10.4385 13.0941L10.9933 11.9845C11.1581 11.6549 11.2083 11.5601 11.2693 11.4809C11.3305 11.4015 11.4017 11.3304 11.481 11.2692C11.5602 11.2082 11.655 11.1579 11.9846 10.9932L13.0942 10.4383C13.2919 10.3395 13.4167 10.1375 13.4167 9.91659C13.4167 9.69564 13.2919 9.49365 13.0942 9.39484L11.9846 8.84001C11.655 8.67523 11.5602 8.62502 11.481 8.56401C11.4017 8.50281 11.3305 8.43164 11.2693 8.35225C11.2083 8.27309 11.1581 8.17826 10.9933 7.84869L10.4385 6.73904Z" fill="#444CE7"/>
  </svg>
)
const AutomaticBtn: FC<IAutomaticBtnProps> = ({
  onClick,
}) => {
  const { t } = useTranslation()

  return (
    <Button className='flex space-x-2 items-center !h-8'
      onClick={onClick}
    >
      {leftIcon}
      <span className='text-xs font-semibold text-primary-600 uppercase'>{t('appDebug.operation.automatic')}</span>
    </Button>
  )
}
export default React.memo(AutomaticBtn)
