<?= $this->extend('Templates/Base') ?>

<?= $this->section('content') ?>
<div class="card">
	<div class="card-header">
		<?= lang('Account.homeText') ?>
	</div>
	<div class="card-body">
		<div class="row">
			<div class="col-sm-4">
				<b><?= lang('Account.homeLabelUsername') ?></b>
			</div>
			<div class="col-sm-8">
				<?= $user->username ?>
			</div>
		</div>
		<div class="row">
			<div class="col-sm-4">
				<b><?= lang('Account.homeLabelEmail') ?></b>
			</div>
			<div class="col-sm-8">
				<?= $user->email ?>
			</div>
		</div>
		<?php if (isset($providers)): ?>
		<div class="row">
			<div class="col-sm-4">
				<b><?= lang('Account.homeLabelSocial') ?></b>
			</div>
			<div class="col-sm-8">
				<?php foreach ($providers as $provider => $state): ?>
					<?php if ($state): ?>
						<?= $provider ?> <br />
					<?php endif; ?>
				<?php endforeach; ?>
			</div>
		</div>
		<?php endif; ?>
	</div>
</div>

<?= $this->endSection() ?>
