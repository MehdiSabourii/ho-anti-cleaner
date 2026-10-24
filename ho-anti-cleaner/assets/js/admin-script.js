/**
 * AssetFlow Cleaner & Optimizer - Admin Scripts
 */

jQuery(document).ready(function ($) {
    'use strict';

    var scanData = null;

    // ثبت پیام در کنسول لاگ زنده
    function logMessage(text, type) {
        type = type || 'system';
        var time = new Date().toLocaleTimeString('fa-IR');
        var $terminal = $('#afc-terminal');
        var line = $('<div class="afc-terminal-line ' + type + '">[' + time + '] ' + text + '</div>');
        $terminal.append(line);
        $terminal.scrollTop($terminal[0].scrollHeight);
    }

    // تغییر زبانه‌ها
    $('.afc-tab-btn').on('click', function (e) {
        e.preventDefault();
        var targetTab = $(this).data('tab');

        $('.afc-tab-btn').removeClass('active');
        $(this).addClass('active');

        $('.afc-tab-pane').removeClass('active');
        $('#' + targetTab).addClass('active');
    });

    // شروع اسکن کامل
    $('#afc-btn-quick-scan, .afc-btn-start-scan').on('click', function (e) {
        e.preventDefault();
        startFullScan();
    });

    function startFullScan() {
        var $btn = $('#afc-btn-quick-scan');
        var $progressBox = $('#afc-progress-box');
        var $progressBar = $('#afc-progress-bar');
        var $progressMsg = $('#afc-progress-msg');

        $btn.prop('disabled', true);
        $progressBox.slideDown();
        $progressBar.css('width', '25%');
        $progressMsg.text(afcData.strings.scanning);
        logMessage('شروع اسکن عمیق سیستم و دیتابیس...', 'system');

        $.ajax({
            url: afcData.ajax_url,
            type: 'POST',
            dataType: 'json',
            data: {
                action: 'afc_scan_system',
                nonce: afcData.nonce
            },
            success: function (response) {
                $progressBar.css('width', '100%');
                setTimeout(function () {
                    $progressBox.slideUp();
                    $btn.prop('disabled', false);
                }, 600);

                if (response.success) {
                    scanData = response.data;
                    renderScanResults(scanData);
                    logMessage('اسکن با موفقیت به پایان رسید. تعداد تهدیدات یافت‌شده: ' + scanData.stats.threats_count, scanData.stats.threats_count > 0 ? 'danger' : 'success');
                } else {
                    logMessage('خطا در انجام اسکن: ' + (response.data.message || 'نامشخص'), 'danger');
                }
            },
            error: function (xhr, status, error) {
                $progressBox.slideUp();
                $btn.prop('disabled', false);
                logMessage('خطای غیرمنتظره در ارتباط AJAX: ' + error, 'danger');
            }
        });
    }

    // رندر نتایج اسکن در UI
    function renderScanResults(data) {
        $('#afc-empty-state').hide();
        $('#afc-scan-results').show();

        // به‌روزرسانی کارت‌های آماری
        var threats = data.stats.threats_count;
        var usersCount = data.hidden_users.length;
        var dbCount = data.options.length + data.tables.length;
        var filesCount = data.infected_files.length;
        var muCount = data.mu_plugins.length;

        $('#afc-val-users').text(usersCount);
        $('#afc-val-db').text(dbCount);
        $('#afc-val-files').text(filesCount);
        $('#afc-val-mu').text(muCount);
        $('#afc-val-core').text((data.core_integrity || []).length);

        var $statusVal = $('#afc-val-status');
        if (threats > 0) {
            $statusVal.text('آلودگی بحرانی (' + threats + ' مورد)').removeClass('afc-status-safe').addClass('afc-status-danger');
            $('#afc-btn-fix-all').fadeIn();
        } else {
            $statusVal.text('کاملاً امن و پاک').removeClass('afc-status-danger').addClass('afc-status-safe');
            $('#afc-btn-fix-all').fadeOut();
        }

        // ۱. رندر کاربران مخفی
        renderUsersSection(data.hidden_users);

        // ۲. رندر جداول و آپشن‌های دیتابیس
        renderDbSection(data.options, data.tables);

        // ۳. رندر mu-plugins
        renderMuSection(data.mu_plugins);

        // ۴. رندر فایل‌های آلوده
        renderInfectedFilesSection(data.infected_files);

        // ۵. رندر فایل‌های php در uploads
        renderUploadsSection(data.uploads_php);

        // ۶. رندر یکپارچگی فایل‌های هسته وردپرس
        renderCoreSection(data.core_integrity || []);

        // ۷. رندر وضعیت آدرس اصلی سایت
        renderSiteurlSection(data.tampered_siteurl || []);
    }

    function renderUsersSection(users) {
        var $badge = $('#afc-badge-users');
        var $body = $('#afc-list-users');
        $body.empty();

        if (users.length === 0) {
            $badge.text('پاک').removeClass('afc-badge-danger').addClass('afc-badge-safe');
            $body.html('<p style="color:#16a34a; margin:0;">هیچ کاربر مخفی یا درپشتی در دیتابیس شناسایی نشد.</p>');
            return;
        }

        $badge.text(users.length + ' مورد خطرناک').removeClass('afc-badge-safe').addClass('afc-badge-danger');
        var html = '<table class="afc-table"><thead><tr><th>شناسه (ID)</th><th>نام کاربری</th><th>ایمیل</th><th>نقش</th><th>تاریخ ثبت</th></tr></thead><tbody>';

        users.forEach(function (u) {
            html += '<tr>' +
                '<td>' + u.ID + '</td>' +
                '<td><strong style="color:#dc2626;"><code>' + u.user_login + '</code></strong></td>' +
                '<td>' + u.user_email + '</td>' +
                '<td><span class="afc-badge afc-badge-danger">مدیر کل (Backdoor)</span></td>' +
                '<td>' + u.registered + '</td>' +
                '</tr>';
        });

        html += '</tbody></table>';
        $body.html(html);
    }

    function renderDbSection(options, tables) {
        var $badge = $('#afc-badge-db');
        var $body = $('#afc-list-db');
        $body.empty();

        var total = options.length + tables.length;
        if (total === 0) {
            $badge.text('پاک').removeClass('afc-badge-danger').addClass('afc-badge-safe');
            $body.html('<p style="color:#16a34a; margin:0;">هیچ جدول یا آپشن مخربی در دیتابیس یافت نشد.</p>');
            return;
        }

        $badge.text(total + ' مورد آلوده').removeClass('afc-badge-safe').addClass('afc-badge-danger');
        var html = '<table class="afc-table"><thead><tr><th>نوع موجودیت</th><th>نام شیء</th><th>جزئیات / مقدار</th></tr></thead><tbody>';

        options.forEach(function (o) {
            html += '<tr><td><span class="afc-badge afc-badge-warning">Option</span></td><td><code>' + o.option_name + '</code></td><td><code>' + o.value + '</code></td></tr>';
        });

        tables.forEach(function (t) {
            html += '<tr><td><span class="afc-badge afc-badge-danger">Table</span></td><td><code>' + t.table_name + '</code></td><td>' + t.row_count + ' رکورد ثبت‌شده</td></tr>';
        });

        html += '</tbody></table>';
        $body.html(html);
    }

    function renderMuSection(muFiles) {
        var $badge = $('#afc-badge-mu');
        var $body = $('#afc-list-mu');
        $body.empty();

        if (muFiles.length === 0) {
            $badge.text('پاک').removeClass('afc-badge-danger').addClass('afc-badge-safe');
            $body.html('<p style="color:#16a34a; margin:0;">پوشه Must-Use Plugins فاقد هرگونه فایل مشکوک است.</p>');
            return;
        }

        $badge.text(muFiles.length + ' فایل پایدار').removeClass('afc-badge-safe').addClass('afc-badge-danger');
        var html = '<table class="afc-table"><thead><tr><th>نام فایل</th><th>مسیر</th><th>علت شناسایی</th></tr></thead><tbody>';

        muFiles.forEach(function (f) {
            html += '<tr>' +
                '<td><strong style="color:#dc2626;">' + f.filename + '</strong></td>' +
                '<td><code>' + f.relative + '</code></td>' +
                '<td><span class="afc-badge afc-badge-danger">' + f.reason + '</span></td>' +
                '</tr>';
        });

        html += '</tbody></table>';
        $body.html(html);
    }

    function renderInfectedFilesSection(files) {
        var $badge = $('#afc-badge-files');
        var $body = $('#afc-list-files');
        $body.empty();

        if (files.length === 0) {
            $badge.text('پاک').removeClass('afc-badge-danger').addClass('afc-badge-safe');
            $body.html('<p style="color:#16a34a; margin:0;">هیچ فایل PHP آلوده‌ای در مسیرهای اسکن‌شده شناسایی نشد.</p>');
            return;
        }

        $badge.text(files.length + ' فایل آلوده').removeClass('afc-badge-safe').addClass('afc-badge-danger');
        var html = '<table class="afc-table"><thead><tr><th>مسیر فایل</th><th>حجم</th><th>نوع تزریق و امضا</th><th>عملیات</th></tr></thead><tbody>';

        files.forEach(function (f) {
            var typeBadge = '';
            var actionBtn = '';

            if (f.is_injected_top) {
                typeBadge = '<span class="afc-badge afc-badge-danger">گیت‌کیپر ورود / مسدودکننده (بالای فایل)</span>';
                actionBtn = '<button class="button button-small button-primary afc-btn-repair-single" data-path="' + f.path + '" style="background:#16a34a; border-color:#15803d;">جراحی و ترمیم فوری</button>';
            } else if (f.is_assetflow) {
                var typeLabel = f.is_injected_bottom ? 'الحاق Asset Flow (قابل جراحی)' : 'فایل مستقل بدافزار Asset Flow';
                typeBadge = '<span class="afc-badge afc-badge-danger">' + typeLabel + '</span>';
                actionBtn = '<button class="button button-small button-primary afc-btn-repair-single" data-path="' + f.path + '">ترمیم و جراحی</button>';
            } else {
                typeBadge = '<span class="afc-badge afc-badge-warning">وب‌شل / اسکریپت مخرب (اکتشافی)</span>';
                actionBtn = '<button class="button button-small button-danger afc-btn-delete-upload-file" data-path="' + f.path + '" style="margin-left:5px;">حذف فایل</button>' +
                            '<button class="button button-small button-secondary afc-btn-repair-single" data-path="' + f.path + '">تلاش برای ترمیم</button>';
            }

            html += '<tr data-filepath="' + f.path + '">' +
                '<td><code>' + f.relative + '</code></td>' +
                '<td>' + f.size + '</td>' +
                '<td>' + typeBadge + ' <small style="display:block; color:#64748b; margin-top:4px;">' + f.signatures + '</small></td>' +
                '<td>' + actionBtn + '</td>' +
                '</tr>';
        });

        html += '</tbody></table>';
        $body.html(html);
    }

    function renderUploadsSection(uploads) {
        var $badge = $('#afc-badge-uploads');
        var $body = $('#afc-list-uploads');
        $body.empty();

        if (!uploads || uploads.length === 0) {
            $badge.text('پاک').removeClass('afc-badge-danger').addClass('afc-badge-safe');
            $body.html('<p style="color:#16a34a; margin:0;">هیچ اسکریپت PHP غیرمجازی در پوشه Uploads وجود ندارد.</p>');
            return;
        }

        $badge.text(uploads.length + ' مورد مشکوک').removeClass('afc-badge-safe').addClass('afc-badge-danger');
        var html = '<table class="afc-table"><thead><tr><th>مسیر فایل</th><th>حجم</th><th>وضعیت</th><th>عملیات</th></tr></thead><tbody>';

        uploads.forEach(function (u) {
            html += '<tr data-filepath="' + u.path + '">' +
                '<td><code>' + u.relative + '</code></td>' +
                '<td>' + u.size + '</td>' +
                '<td><span class="afc-badge afc-badge-danger">اسکریپت PHP غیرمجاز</span></td>' +
                '<td><button class="button button-small button-link-delete afc-btn-delete-upload-file" data-path="' + u.path + '">حذف این فایل</button></td>' +
                '</tr>';
        });

        html += '</tbody></table>';
        $body.html(html);
    }


    function renderCoreSection(coreItems) {
        var $badge = $('#afc-badge-core');
        var $body = $('#afc-list-core');
        $body.empty();

        if (!coreItems || coreItems.length === 0) {
            $badge.text('پاک').removeClass('afc-badge-danger').addClass('afc-badge-safe');
            $body.html('<p style="color:#16a34a; margin:0;"><span class="dashicons dashicons-yes"></span> تمامی فایل‌های هسته وردپرس با مرجع رسمی مطابقت دارند و هیچ فایل غیررسمی یا ناشناخته‌ای در هسته یافت نشد.</p>');
            return;
        }

        $badge.text(coreItems.length + ' ناهماهنگی هسته').removeClass('afc-badge-safe').addClass('afc-badge-danger');
        var html = '<table class="afc-table"><thead><tr><th>مسیر فایل در هسته</th><th>وضعیت</th><th>توضیحات</th><th>عملیات</th></tr></thead><tbody>';

        coreItems.forEach(function (item) {
            var isModified = (item.type === 'modified');
            var typeBadge = isModified 
                ? '<span class="afc-badge afc-badge-warning">تغییریافته (عدم تطبیق هش)</span>'
                : '<span class="afc-badge afc-badge-danger">فایل غیررسمی / فاقد مرجع رسمی</span>';

            var actionsHtml = '';
            if (isModified) {
                actionsHtml += '<button class="button button-small button-primary afc-btn-restore-core" data-path="' + item.path + '" style="margin-left:5px;"><span class="dashicons dashicons-update"></span> بازگردانی از WordPress.org</button>' +
                               '<button class="button button-small afc-btn-diff" data-path="' + item.path + '" style="margin-left:5px;"><span class="dashicons dashicons-visibility"></span> مشاهده تفاوت (Diff)</button>' +
                               '<button class="button button-small button-link-delete afc-btn-delete-core" data-path="' + item.path + '"><span class="dashicons dashicons-trash"></span> حذف با قرنطینه</button>';
            } else {
                actionsHtml += '<button class="button button-small button-danger afc-btn-delete-core" data-path="' + item.path + '" style="background:#dc2626; color:#fff; border-color:#b91c1c;"><span class="dashicons dashicons-trash"></span> حذف فایل غیررسمی (با پشتیبان در قرنطینه)</button>';
            }

            html += '<tr data-filepath="' + item.path + '">' +
                '<td><code>' + (item.relative || item.path) + '</code></td>' +
                '<td>' + typeBadge + '</td>' +
                '<td>' + (item.description || '') + '</td>' +
                '<td>' + actionsHtml + '</td>' +
                '</tr>';
        });

        html += '</tbody></table>';
        $body.html(html);
    }

    function renderSiteurlSection(siteurlItems) {
        var $box = $('#afc-box-siteurl');
        var $body = $('#afc-list-siteurl');
        $body.empty();

        if (!siteurlItems || siteurlItems.length === 0) {
            $box.hide();
            return;
        }

        $box.show();
        var html = '<table class="afc-table"><thead><tr><th>کلید تنظیمات</th><th>مقدار آلوده در دیتابیس</th><th>آدرس موثق</th><th>عملیات اصلاحی</th></tr></thead><tbody>';

        siteurlItems.forEach(function (item) {
            html += '<tr>' +
                '<td><code>' + item.option + '</code></td>' +
                '<td><strong style="color:#dc2626;">' + item.current_value + '</strong></td>' +
                '<td><strong style="color:#16a34a;">' + (item.trusted_value || 'تشخیص خودکار از دامنه') + '</strong></td>' +
                '<td><button class="button button-danger afc-btn-restore-siteurl" data-trusted="' + (item.trusted_value || '') + '"><span class="dashicons dashicons-undo"></span> اصلاح و بازگردانی فوری آدرس سایت</button></td>' +
                '</tr>';
        });

        html += '</tbody></table>';
        $body.html(html);
    }

    // حذف تکی فایل از آپلودها
    $(document).on('click', '.afc-btn-delete-upload-file', function (e) {
        e.preventDefault();
        var $btn = $(this);
        var filePath = $btn.data('path');
        var $row = $btn.closest('tr');

        if (!confirm('آیا از حذف این فایل مشکوک مطمئن هستید؟')) {
            return;
        }

        $btn.prop('disabled', true).text('در حال حذف...');

        $.ajax({
            url: afcData.ajax_url,
            type: 'POST',
            dataType: 'json',
            data: {
                action: 'afc_delete_single_file',
                file_path: filePath,
                nonce: afcData.nonce
            },
            success: function (res) {
                if (res.success) {
                    $row.fadeOut(300, function () { $(this).remove(); });
                    logMessage('فایل حذف شد: ' + filePath, 'success');
                } else {
                    $btn.prop('disabled', false).text('تلاش مجدد');
                    alert(res.data.message || 'خطا در حذف فایل');
                }
            },
            error: function () {
                $btn.prop('disabled', false).text('تلاش مجدد');
                alert(afcData.strings.error_occurred);
            }
        });
    });

    // ترمیم تکی یک فایل
    $(document).on('click', '.afc-btn-repair-single', function (e) {
        e.preventDefault();
        var $btn = $(this);
        var filePath = $btn.data('path');
        var $row = $btn.closest('tr');

        $btn.prop('disabled', true).text('در حال ترمیم...');

        $.ajax({
            url: afcData.ajax_url,
            type: 'POST',
            dataType: 'json',
            data: {
                action: 'afc_repair_single_file',
                file_path: filePath,
                nonce: afcData.nonce
            },
            success: function (response) {
                if (response.success) {
                    $row.css('background', '#dcfce7');
                    $btn.replaceWith('<span class="afc-badge afc-badge-safe">ترمیم شد</span>');
                    logMessage('فایل ترمیم شد: ' + filePath, 'success');
                } else {
                    $btn.prop('disabled', false).text('تلاش مجدد');
                    alert(response.data.message);
                    logMessage('خطا در ترمیم فایل: ' + filePath + ' (' + response.data.message + ')', 'danger');
                }
            },
            error: function () {
                $btn.prop('disabled', false).text('تلاش مجدد');
                alert(afcData.strings.error_occurred);
            }
        });
    });

    // پاک‌سازی دیتابیس
    $('#afc-act-clean-db').on('click', function (e) {
        e.preventDefault();
        var $btn = $(this);
        $btn.prop('disabled', true);
        logMessage('در حال پاک‌سازی دیتابیس...', 'system');

        $.ajax({
            url: afcData.ajax_url,
            type: 'POST',
            dataType: 'json',
            data: {
                action: 'afc_clean_database',
                nonce: afcData.nonce
            },
            success: function (res) {
                $btn.prop('disabled', false);
                if (res.success) {
                    res.data.log.forEach(function (l) {
                        logMessage(l, 'success');
                    });
                    alert('دیتابیس با موفقیت پاک‌سازی شد.');
                    startFullScan();
                }
            }
        });
    });

    // پاک‌سازی mu-plugins
    $('#afc-act-clean-mu').on('click', function (e) {
        e.preventDefault();
        var $btn = $(this);
        $btn.prop('disabled', true);
        logMessage('در حال حذف فایل‌های mu-plugins...', 'system');

        $.ajax({
            url: afcData.ajax_url,
            type: 'POST',
            dataType: 'json',
            data: {
                action: 'afc_clean_mu_plugins',
                nonce: afcData.nonce
            },
            success: function (res) {
                $btn.prop('disabled', false);
                if (res.success) {
                    res.data.log.forEach(function (l) {
                        logMessage(l, 'success');
                    });
                    alert('پوشه mu-plugins پاک‌سازی شد.');
                    startFullScan();
                }
            }
        });
    });

    // ترمیم همه فایل‌های آلوده
    $('#afc-act-clean-files').on('click', function (e) {
        e.preventDefault();
        if (!scanData || !scanData.infected_files || scanData.infected_files.length === 0) {
            alert('ابتدا اسکن را اجرا کنید یا فایلی برای ترمیم وجود ندارد.');
            return;
        }

        if (!confirm(afcData.strings.confirm_clean)) {
            return;
        }

        var filePaths = scanData.infected_files.map(function (f) { return f.path; });
        var $btn = $(this);
        $btn.prop('disabled', true);
        logMessage('شروع عملیات جراحی و ترمیم دسته‌جمعی فایل‌ها...', 'system');

        $.ajax({
            url: afcData.ajax_url,
            type: 'POST',
            dataType: 'json',
            data: {
                action: 'afc_repair_all_files',
                files: filePaths,
                nonce: afcData.nonce
            },
            success: function (res) {
                $btn.prop('disabled', false);
                if (res.success) {
                    res.data.logs.forEach(function (l) {
                        logMessage(l, 'success');
                    });
                    alert('تعداد ' + res.data.repaired + ' فایل ترمیم شد و ' + res.data.deleted + ' فایل مخرب حذف گردید.');
                    startFullScan();
                }
            }
        });
    });

    // پاک‌سازی uploads
    $('#afc-act-clean-uploads').on('click', function (e) {
        e.preventDefault();
        var $btn = $(this);
        $btn.prop('disabled', true);

        $.ajax({
            url: afcData.ajax_url,
            type: 'POST',
            dataType: 'json',
            data: {
                action: 'afc_clean_uploads_php',
                nonce: afcData.nonce
            },
            success: function (res) {
                $btn.prop('disabled', false);
                if (res.success) {
                    res.data.log.forEach(function (l) {
                        logMessage(l, 'success');
                    });
                    alert('پوشه رسانه پاک‌سازی شد.');
                    startFullScan();
                }
            }
        });
    });

    // دکمه پاک‌سازی یک‌کلیکه همه موارد
    $('#afc-btn-fix-all').on('click', function (e) {
        e.preventDefault();
        if (!confirm(afcData.strings.confirm_all)) {
            return;
        }

        logMessage('>>> آغاز عملیات جامع پاک‌سازی و رفع آلودگی کلی سایت...', 'warning');

        // مرحله ۱: پاک‌سازی دیتابیس
        $.post(afcData.ajax_url, { action: 'afc_clean_database', nonce: afcData.nonce }, function () {
            logMessage('مرحله ۱: دیتابیس و کاربران مخفی پاک‌سازی شدند.', 'success');

            // مرحله ۲: پاک‌سازی mu-plugins
            $.post(afcData.ajax_url, { action: 'afc_clean_mu_plugins', nonce: afcData.nonce }, function () {
                logMessage('مرحله ۲: درپشتی‌های mu-plugins حذف شدند.', 'success');

                // مرحله ۳: پاک‌سازی آپلودها
                $.post(afcData.ajax_url, { action: 'afc_clean_uploads_php', nonce: afcData.nonce }, function () {
                    logMessage('مرحله ۳: اسکریپت‌های uploads بررسی شدند.', 'success');

                    // مرحله ۴: ترمیم فایل‌ها
                    if (scanData && scanData.infected_files && scanData.infected_files.length > 0) {
                        var filePaths = scanData.infected_files.map(function (f) { return f.path; });
                        $.post(afcData.ajax_url, { action: 'afc_repair_all_files', files: filePaths, nonce: afcData.nonce }, function (fileRes) {
                            logMessage('مرحله ۴: فایل‌های PHP با موفقیت جراحی و ترمیم شدند.', 'success');
                            alert('عملیات پاک‌سازی جامع به پایان رسید. اسکن مجدد انجام می‌شود.');
                            startFullScan();
                        });
                    } else {
                        alert('عملیات با موفقیت به پایان رسید.');
                        startFullScan();
                    }
                });
            });
        });
    });

    // بهینه‌سازی دیتابیس
    $('#afc-act-optimize-db').on('click', function (e) {
        e.preventDefault();
        var $btn = $(this);
        $btn.prop('disabled', true);
        logMessage('شروع بهینه‌سازی، دیفرگ جداول و پاک‌سازی حافظه موقت دیتابیس...', 'system');

        $.ajax({
            url: afcData.ajax_url,
            type: 'POST',
            dataType: 'json',
            data: {
                action: 'afc_optimize_database',
                nonce: afcData.nonce
            },
            success: function (res) {
                $btn.prop('disabled', false);
                if (res.success) {
                    res.data.report.log.forEach(function (l) {
                        logMessage(l, 'success');
                    });
                    alert('دیتابیس با موفقیت بهینه‌سازی شد!');
                }
            }
        });
    });

    // دریافت و کپی Salts
    $('#afc-btn-get-salts').on('click', function (e) {
        e.preventDefault();
        $.post(afcData.ajax_url, { action: 'afc_generate_salts', nonce: afcData.nonce }, function (res) {
            if (res.success) {
                $('#afc-salts-text').val(res.data.salts);
                $('#afc-salts-container').slideDown();
                logMessage('کلیدهای امنیتی تصادفی جدید تولید شدند.', 'system');
            }
        });
    });

    $('#afc-copy-salts').on('click', function (e) {
        e.preventDefault();
        var copyText = document.getElementById('afc-salts-text');
        copyText.select();
        copyText.setSelectionRange(0, 99999);
        navigator.clipboard.writeText(copyText.value);
        $(this).text('کپی شد!');
        setTimeout(function () {
            $('#afc-copy-salts').text('کپی در کلیپ‌بورد');
        }, 2000);
    });

    // پاک‌سازی کنسول لاگ
    $('#afc-btn-clear-logs').on('click', function (e) {
        e.preventDefault();
        $('#afc-terminal').empty();
        logMessage('کنسول پاک شد.', 'system');
    });

    // ==========================================
    // اکشن‌های سپر ضد تزریق و امنیت فعال
    // ==========================================

    function updateLockTable(files) {
        var $tbody = $('#afc-table-file-locks tbody');
        if (!files || Object.keys(files).length === 0) return;

        $tbody.empty();
        Object.keys(files).forEach(function (name) {
            var item = files[name];
            var relPath = item.path.replace(/\\/g, '/');
            var badge = item.locked
                ? '<span class="afc-badge afc-badge-safe"><span class="dashicons dashicons-yes"></span> قفل‌شده و ضد تزریق</span>'
                : '<span class="afc-badge afc-badge-warning"><span class="dashicons dashicons-warning"></span> قابل نوشتن (توصیه: قفل شود)</span>';
            var writable = item.writable
                ? '<span style="color:#dc2626; font-weight:bold;">بله (آسیب‌پذیر به بازنویسی)</span>'
                : '<span style="color:#16a34a; font-weight:bold;">خیر (محافظت‌شده)</span>';

            var row = '<tr>' +
                '<td><strong><code>' + name + '</code></strong></td>' +
                '<td><code style="font-size:11px;">' + relPath + '</code></td>' +
                '<td><span class="afc-badge">' + item.perms + '</span></td>' +
                '<td>' + badge + '</td>' +
                '<td>' + writable + '</td>' +
                '</tr>';
            $tbody.append(row);
        });
    }

    // قفل کردن فایل‌ها (0444)
    $('#afc-btn-lock-files').on('click', function (e) {
        e.preventDefault();
        var $btn = $(this);
        $btn.prop('disabled', true);
        logMessage('در حال اعمال قفل سطح 0444 روی کلیه فایل‌های حساس وردپرس...', 'warning');

        $.post(afcData.ajax_url, {
            action: 'afc_toggle_file_lock',
            lock_action: 'lock',
            nonce: afcData.nonce
        }, function (res) {
            $btn.prop('disabled', false);
            if (res.success) {
                $('#afc-val-locked').text('فعال (0444)');
                updateLockTable(res.data.files);
                logMessage(res.data.message, 'success');
                alert(res.data.message);
            }
        });
    });

    // باز کردن موقت قفل فایل‌ها (0644)
    $('#afc-btn-unlock-files').on('click', function (e) {
        e.preventDefault();
        var $btn = $(this);
        $btn.prop('disabled', true);
        logMessage('در حال باز کردن قفل فایل‌ها جهت ویرایش یا به‌روزرسانی (0644)...', 'system');

        $.post(afcData.ajax_url, {
            action: 'afc_toggle_file_lock',
            lock_action: 'unlock',
            nonce: afcData.nonce
        }, function (res) {
            $btn.prop('disabled', false);
            if (res.success) {
                $('#afc-val-locked').text('باز (0644)');
                updateLockTable(res.data.files);
                logMessage(res.data.message, 'warning');
                alert(res.data.message);
            }
        });
    });

    // سوئیچ خودترمیم‌کننده
    $('#afc-toggle-self-heal').on('change', function () {
        var enable = $(this).is(':checked') ? 1 : 0;
        $.post(afcData.ajax_url, {
            action: 'afc_toggle_self_healing',
            enable: enable,
            nonce: afcData.nonce
        }, function (res) {
            if (res.success) {
                logMessage(res.data.message, enable ? 'success' : 'warning');
            }
        });
    });

    // سوئیچ فایروال
    $('#afc-toggle-waf').on('change', function () {
        var enable = $(this).is(':checked') ? 1 : 0;
        $.post(afcData.ajax_url, {
            action: 'afc_toggle_firewall',
            enable: enable,
            nonce: afcData.nonce
        }, function (res) {
            if (res.success) {
                logMessage(res.data.message, enable ? 'success' : 'warning');
            }
        });
    });

    // استقرار سپر محافظتی Uploads و wp-includes
    $('#afc-btn-install-shields').on('click', function (e) {
        e.preventDefault();
        var $btn = $(this);
        $btn.prop('disabled', true);
        $.post(afcData.ajax_url, {
            action: 'afc_install_execution_shields',
            nonce: afcData.nonce
        }, function (res) {
            $btn.prop('disabled', false);
            if (res.success) {
                res.data.log.forEach(function (l) {
                    logMessage(l, 'success');
                });
                alert('سپر ضد اجرای PHP با موفقیت در پوشه‌های uploads و wp-includes نصب شد.');
            }
        });
    });

    // سخت‌سازی wp-config.php
    $('#afc-btn-harden-config').on('click', function (e) {
        e.preventDefault();
        var $btn = $(this);
        $btn.prop('disabled', true);
        $.post(afcData.ajax_url, {
            action: 'afc_apply_wp_config_hardening',
            nonce: afcData.nonce
        }, function (res) {
            $btn.prop('disabled', false);
            if (res.success) {
                logMessage(res.data.message, 'success');
                alert(res.data.message);
            } else {
                alert(res.data.message || 'خطا در ویرایش wp-config.php');
            }
        });
    });

    // پاک‌سازی کران‌جاب‌های مشکوک
    $('#afc-btn-clean-crons').on('click', function (e) {
        e.preventDefault();
        var $btn = $(this);
        $btn.prop('disabled', true);
        $.post(afcData.ajax_url, {
            action: 'afc_clean_cron_jobs',
            nonce: afcData.nonce
        }, function (res) {
            $btn.prop('disabled', false);
            if (res.success) {
                logMessage(res.data.message, 'success');
                alert(res.data.message);
                location.reload();
            }
        });
    });

    // پاک‌کردن تاریخچه حوادث امنیتی
    $('#afc-btn-clear-sec-logs').on('click', function (e) {
        e.preventDefault();
        $.post(afcData.ajax_url, {
            action: 'afc_clear_security_logs',
            nonce: afcData.nonce
        }, function (res) {
            if (res.success) {
                $('#afc-sec-logs-list').html('<p style="color:#64748b; margin:0;">هیچ تهاجم یا تزریق کدی در بازه اخیر ثبت نشده است.</p>');
                logMessage(res.data.message, 'system');
            }
        });
    });

    // عملیات بازگردانی از قرنطینه (Rollback)
    $(document).on('click', '.afc-btn-rollback', function (e) {
        e.preventDefault();
        var $btn = $(this);
        var backupId = $btn.data('backup-id');

        if (!confirm('آیا از بازگردانی (Rollback) این فایل به حالت اولیه اطمینان دارید؟')) {
            return;
        }

        $btn.prop('disabled', true).text('در حال بازگردانی...');
        logMessage('درخواست بازگردانی برای بسته ' + backupId, 'system');

        $.post(afcData.ajax_url, {
            action: 'afc_quarantine_rollback',
            nonce: afcData.nonce,
            backup_id: backupId
        }, function (res) {
            if (res.success) {
                logMessage(res.data.message, 'success');
                alert(res.data.message);
                location.reload();
            } else {
                logMessage('خطا در بازگردانی: ' + (res.data.message || 'خطای سرور'), 'error');
                alert(res.data.message || 'خطا در بازگردانی');
                $btn.prop('disabled', false).text('بازگردانی مجدد');
            }
        });
    });

    // بازگردانی فایل هسته از منبع رسمی WordPress.org
    $(document).on('click', '.afc-btn-restore-core', function (e) {
        e.preventDefault();
        var $btn = $(this);
        var filePath = $btn.data('file-path');
        var findingId = $btn.data('finding-id');

        if (!confirm('فایل آلوده ابتدا در قرنطینه امن ذخیره شده و سپس با نسخه رسمی WordPress.org جایگزین می‌شود. ادامه می‌دهید؟')) {
            return;
        }

        $btn.prop('disabled', true).text('در حال دریافت نسخه رسمی...');
        logMessage('درخواست دانلود و جایگزینی فایل هسته: ' + filePath, 'system');

        $.post(afcData.ajax_url, {
            action: 'afc_restore_core_file',
            nonce: afcData.nonce,
            file_path: filePath,
            finding_id: findingId
        }, function (res) {
            if (res.success) {
                logMessage(res.data.message, 'success');
                alert(res.data.message);
                $btn.replaceWith('<span style="color:#16a34a; font-weight:bold;">ترمیم شد</span>');
            } else {
                logMessage('خطا: ' + (res.data.message || 'خطا در بازگردانی'), 'error');
                alert(res.data.message || 'خطا در بازگردانی');
                $btn.prop('disabled', false).text('تلاش مجدد');
            }
        });
    });

    // مشاهده تفاوت فایل (Diff Viewer)
    $(document).on('click', '.afc-btn-view-diff', function (e) {
        e.preventDefault();
        var filePath = $(this).data('file-path');

        logMessage('در حال دریافت گزارش تفاوت (Diff) برای: ' + filePath, 'system');
        $.post(afcData.ajax_url, {
            action: 'afc_get_file_diff',
            nonce: afcData.nonce,
            file_path: filePath
        }, function (res) {
            if (res.success) {
                alert("تفاوت فایل محلی با نسخه رسمی WordPress.org:\n\n" + res.data.diff);
            } else {
                alert(res.data.message || 'خطا در محاسبه Diff');
            }
        });
    });

    // به‌روزرسانی جدول قرنطینه
    $('#afc-btn-refresh-quarantine').on('click', function(e) {
        e.preventDefault();
        location.reload();
    });


    // بارگذاری پویای لاگ‌های امنیتی
    function loadSecurityLogs() {
        var $list = $('#afc-sec-logs-list');
        $list.html('<p style="color:#64748b; margin:0;"><span class="dashicons dashicons-update afc-spin"></span> در حال بارگذاری تاریخچه حوادث...</p>');

        $.ajax({
            url: afcData.ajax_url,
            type: 'POST',
            dataType: 'json',
            data: {
                action: 'afc_get_security_logs',
                nonce: afcData.nonce
            },
            success: function (res) {
                if (res.success && res.data.logs && res.data.logs.length > 0) {
                    var html = '<table class="afc-table"><thead><tr><th>زمان</th><th>سطح خطر</th><th>نوع رویداد</th><th>شرح رویداد</th></tr></thead><tbody>';
                    res.data.logs.forEach(function (lg) {
                        var sevBadge = '<span class="afc-badge afc-badge-safe">عادی</span>';
                        if (lg.severity === 'critical') sevBadge = '<span class="afc-badge afc-badge-danger">بحرانی</span>';
                        else if (lg.severity === 'high') sevBadge = '<span class="afc-badge afc-badge-warning">بالا</span>';
                        else if (lg.severity === 'medium') sevBadge = '<span class="afc-badge">متوسط</span>';

                        var typeLabel = lg.type;
                        if (lg.type === 'siteurl_tamper_blocked') typeLabel = 'مهار دستکاری آدرس سایت';
                        else if (lg.type === 'self_healed') typeLabel = 'ترمیم خودکار فایل';
                        else if (lg.type === 'firewall_blocked_payload') typeLabel = 'بلاک RCE فایروال';
                        else if (lg.type === 'firewall_blocked_cookie') typeLabel = 'بلاک کوکی مهاجم';
                        else if (lg.type === 'file_deleted') typeLabel = 'حذف امن با قرنطینه';
                        else if (lg.type === 'permissions_enforced') typeLabel = 'اصلاح مجوزهای فایل';
                        else if (lg.type === 'scan_completed') typeLabel = 'پایان اسکن سیستم';
                        else if (lg.type === 'database_cleaned') typeLabel = 'پاک‌سازی دیتابیس';
                        else if (lg.type === 'siteurl_restored') typeLabel = 'بازگردانی آدرس سایت';

                        html += '<tr>' +
                            '<td><code style="font-size:11px;">' + lg.time + '</code></td>' +
                            '<td>' + sevBadge + '</td>' +
                            '<td><strong>' + typeLabel + '</strong></td>' +
                            '<td>' + lg.message + '</td>' +
                            '</tr>';
                    });
                    html += '</tbody></table>';
                    $list.html(html);
                } else {
                    $list.html('<p style="color:#64748b; margin:0;">هیچ تهاجم یا تزریق کدی در بازه اخیر ثبت نشده است.</p>');
                }
            },
            error: function () {
                $list.html('<p style="color:#dc2626; margin:0;">خطا در دریافت لاگ‌ها.</p>');
            }
        });
    }

    $('#afc-btn-refresh-sec-logs').on('click', function (e) {
        e.preventDefault();
        loadSecurityLogs();
    });

    $('.afc-tab-btn[data-tab="tab-logs"]').on('click', function () {
        loadSecurityLogs();
    });

    // عملیات بازگردانی فایل رسمی هسته از WordPress.org
    $(document).on('click', '.afc-btn-restore-core', function (e) {
        e.preventDefault();
        var $btn = $(this);
        var path = $btn.data('path');
        if (!confirm('آیا از بازگردانی این فایل با نسخه رسمی و دست‌نخورده از سرور رسمی WordPress.org اطمینان دارید؟')) return;

        $btn.prop('disabled', true).text('در حال دریافت از WordPress.org...');
        logMessage('در حال بازگردانی فایل رسمی هسته: ' + path, 'system');

        $.ajax({
            url: afcData.ajax_url,
            type: 'POST',
            dataType: 'json',
            data: {
                action: 'afc_restore_core_file',
                nonce: afcData.nonce,
                file_path: path
            },
            success: function (res) {
                if (res.success) {
                    logMessage(res.data.message, 'success');
                    $btn.closest('tr').fadeOut(400, function () { $(this).remove(); });
                } else {
                    logMessage('خطا در بازگردانی: ' + (res.data.message || 'خطای نامشخص'), 'danger');
                    $btn.prop('disabled', false).text('تلاش مجدد');
                }
            },
            error: function (xhr, s, err) {
                logMessage('خطای ارتباط با سرور: ' + err, 'danger');
                $btn.prop('disabled', false).text('تلاش مجدد');
            }
        });
    });

    // عملیات حذف فایل غیررسمی هسته با پشتیبان در قرنطینه
    $(document).on('click', '.afc-btn-delete-core', function (e) {
        e.preventDefault();
        var $btn = $(this);
        var path = $btn.data('path');
        if (!confirm('آیا از حذف این فایل غیررسمی اطمینان دارید؟ نسخه پشتیبان قبل از حذف به صورت امن در قرنطینه ذخیره خواهد شد.')) return;

        $btn.prop('disabled', true).text('در حال حذف...');
        logMessage('در حال انتقال به قرنطینه و حذف: ' + path, 'system');

        $.ajax({
            url: afcData.ajax_url,
            type: 'POST',
            dataType: 'json',
            data: {
                action: 'afc_delete_single_file',
                nonce: afcData.nonce,
                file_path: path
            },
            success: function (res) {
                if (res.success) {
                    logMessage(res.data.message, 'success');
                    $btn.closest('tr').fadeOut(400, function () { $(this).remove(); });
                } else {
                    logMessage('خطا در حذف: ' + (res.data.message || 'خطای نامشخص'), 'danger');
                    $btn.prop('disabled', false).text('حذف');
                }
            },
            error: function (xhr, s, err) {
                logMessage('خطای ارتباط با سرور: ' + err, 'danger');
                $btn.prop('disabled', false).text('حذف');
            }
        });
    });

    // عملیات بازگردانی فوری آدرس سایت
    $(document).on('click', '.afc-btn-restore-siteurl', function (e) {
        e.preventDefault();
        var $btn = $(this);
        var trusted = $btn.data('trusted');
        if (!confirm('آیا از اصلاح و بازگردانی آدرس سایت به آدرس معتبر اطمینان دارید؟')) return;

        $btn.prop('disabled', true).text('در حال اصلاح...');
        logMessage('در حال بازگردانی آدرس سایت در دیتابیس...', 'system');

        $.ajax({
            url: afcData.ajax_url,
            type: 'POST',
            dataType: 'json',
            data: {
                action: 'afc_restore_siteurl',
                nonce: afcData.nonce,
                target_url: trusted
            },
            success: function (res) {
                if (res.success) {
                    logMessage('آدرس سایت با موفقیت اصلاح شد.', 'success');
                    $('#afc-box-siteurl').slideUp();
                } else {
                    logMessage('خطا در اصلاح آدرس سایت: ' + (res.data.message || 'نامشخص'), 'danger');
                    $btn.prop('disabled', false).text('تلاش مجدد');
                }
            },
            error: function (xhr, s, err) {
                logMessage('خطای ارتباط با سرور: ' + err, 'danger');
                $btn.prop('disabled', false).text('تلاش مجدد');
            }
        });
    });

});
